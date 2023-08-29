/*
Copyright 2023 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package tidydns

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/neticdk/tidydns-go/pkg/tidydns"
	log "github.com/sirupsen/logrus"

	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

var (
	errorSkip = fmt.Errorf("skipping record")
)

type tidyDNSProvider struct {
	provider.BaseProvider
	domainFilter endpoint.DomainFilter
	zoneIDFilter provider.ZoneIDFilter
	dryRun       bool
	client       tidydns.TidyDNSClient
}

type groupKey struct {
	name  string
	rType string
}

// NewTidyDNSProvider initializes a new Dnsimple based provider
func NewTidyDNSProvider(domainFilter endpoint.DomainFilter, zoneIDFilter provider.ZoneIDFilter, endpoint string, dryRun bool) (provider.Provider, error) {
	username := os.Getenv("TIDYDNS_USER")
	if len(username) == 0 {
		return nil, fmt.Errorf("no tidydns username provided")
	}

	password := os.Getenv("TIDYDNS_PASS")
	if len(password) == 0 {
		return nil, fmt.Errorf("no tidydns password provided")
	}

	if len(endpoint) == 0 {
		return nil, fmt.Errorf("no tidydns endpoint provided")
	}

	provider := &tidyDNSProvider{
		domainFilter: domainFilter,
		zoneIDFilter: zoneIDFilter,
		dryRun:       dryRun,
		client:       tidydns.New(endpoint, username, password),
	}
	return provider, nil
}

func (t *tidyDNSProvider) Records(ctx context.Context) (endpoints []*endpoint.Endpoint, err error) {
	zones, err := t.client.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	grouped := make(map[groupKey][]*tidydns.RecordInfo)
	for _, z := range zones {
		if !(t.domainFilter.Match(z.Name) || t.domainFilter.MatchParent(z.Name)) || !t.zoneIDFilter.Match(strconv.Itoa(z.ID)) {
			log.Debugf("Skipping zone %d due to zone filter", z.ID)
			continue
		}

		records, err := t.client.ListRecords(ctx, z.ID)
		log.Debugf("Got %d records for zone %d", len(records), z.ID)
		if err != nil {
			return nil, err
		}

		for _, r := range records {
			rType := ""
			switch r.Type {
			case tidydns.RecordTypeA:
				rType = "A"
			case tidydns.RecordTypeCNAME:
				rType = "CNAME"
			case tidydns.RecordTypeTXT:
				rType = "TXT"
				r.Destination = fmt.Sprintf("\"%s\"", r.Destination) // external-dns expects quotation marks around the TXT records
			default:
				continue
			}

			dnsName := r.Name + "." + z.Name
			if len(strings.Trim(r.Name, ".")) == 0 {
				dnsName = z.Name
			}
			gId := groupKey{name: dnsName, rType: rType}
			_, ok := grouped[gId]
			if !ok {
				grouped[gId] = make([]*tidydns.RecordInfo, 0)
			}
			grouped[gId] = append(grouped[gId], r)
		}
	}

	for k, v := range grouped {
		targets := make([]string, 0)
		ttl := endpoint.TTL(0)
		description := ""
		for _, r := range v {
			targets = append(targets, r.Destination)
			ttl = endpoint.TTL(r.TTL)
			description = r.Description
		}
		endpoints = append(endpoints, endpoint.NewEndpointWithTTL(k.name, k.rType, ttl, targets...).WithSetIdentifier(description))
	}

	log.Debugf("Returning endpoints: %+v", endpoints)

	return endpoints, nil
}

func (t *tidyDNSProvider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	if !changes.HasChanges() {
		return nil
	}

	zones, err := t.client.ListZones(ctx)
	if err != nil {
		return err
	}

	for _, c := range changes.Create {
		log.Tracef("Handling creation record %+v", c)

		z := findSuitableZones(zones, c.DNSName)
		if z == nil {
			log.Debugf("Skipping create of record %s because no hosted zone matching record DNS Name was detected", c.DNSName)
			continue
		}

		rType := convertRecordType(c.RecordType)
		if rType == tidydns.RecordType(-1) {
			log.Warnf("Skipping create of record %s because it has unsupported record type %s", c.DNSName, c.RecordType)
			continue
		}

		infos := createRecordInfo(c, z.Name)
		for _, in := range infos {
			log.Infof("Create record %s (%s) of type %s in zone %s with target %s", c.DNSName, in.Name, c.RecordType, z.Name, in.Destination)
			if !t.dryRun {
				_, err = t.client.CreateRecord(ctx, z.ID, in)
				if err != nil {
					return err
				}
			}
		}
	}

	for i, u := range changes.UpdateNew {
		log.Tracef("Handling update record %+v", u)

		z := findSuitableZones(zones, u.DNSName)
		if z == nil {
			log.Debugf("Skipping update of record %s because no hosted zone matching record DNS Name was detected", u.DNSName)
			continue
		}

		records, err := t.findRecords(ctx, u, z)
		if err != nil {
			if err == errorSkip {
				continue
			} else {
				return err
			}
		}

		for _, r := range records {
			if r.Description == u.SetIdentifier {
				infos := createRecordInfo(u, z.Name)
				log.Tracef("infos: %+v", infos)
				for j, in := range infos {
					if changes.UpdateOld[i].Targets[j] == r.Destination {
						log.Infof("Update record %s (%s/%d) of type %s in zone %s with target %s", u.DNSName, in.Name, r.ID, u.RecordType, z.Name, in.Destination)
						if !t.dryRun {
							err := t.client.UpdateRecord(ctx, z.ID, r.ID, in)
							if err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}

	for _, d := range changes.Delete {
		log.Tracef("Handling deletion record %+v", d)

		z := findSuitableZones(zones, d.DNSName)
		if z == nil {
			log.Debugf("Skipping delete of record %s because no hosted zone matching record DNS Name was detected", d.DNSName)
			continue
		}

		records, err := t.findRecords(ctx, d, z)
		if err != nil {
			if err == errorSkip {
				continue
			} else {
				return err
			}
		}

		for _, r := range records {
			if r.Description == d.SetIdentifier {
				for _, ta := range d.Targets {
					if ta == r.Destination {
						log.Infof("Deleting record %s (%s/%d) of type %s in zone %s with target %s", d.DNSName, r.Name, r.ID, d.RecordType, z.Name, ta)
						if !t.dryRun {
							err := t.client.DeleteRecord(ctx, z.ID, r.ID)
							if err != nil {
								return err
							}
						}
					}
				}
			}
		}
	}

	return nil
}

// findRecords retrives DNS records matching the given endpoint within the given zone
func (t *tidyDNSProvider) findRecords(ctx context.Context, e *endpoint.Endpoint, z *tidydns.ZoneInfo) ([]*tidydns.RecordInfo, error) {
	rType := convertRecordType(e.RecordType)
	if rType == tidydns.RecordType(-1) {
		log.Warnf("Skipping record %s because it has unsupported record type %s", e.DNSName, e.RecordType)
		return nil, errorSkip
	}

	hostname := strings.TrimSuffix(strings.TrimSuffix(e.DNSName, z.Name), ".")
	records, err := t.client.FindRecord(ctx, z.ID, hostname, rType)
	log.Tracef("Found records %d based on hostname %s and type %+v", len(records), hostname, rType)
	if err != nil {
		return nil, err
	}

	for _, r := range records {
		if r.Type == tidydns.RecordTypeTXT {
			r.Destination = fmt.Sprintf("\"%s\"", r.Destination) // external-dns expects quotation marks around the TXT records
		}
	}

	return records, nil
}

// findSuitableZones returns DNS zone matching the longest part of the domain of the hostname
func findSuitableZones(zones []*tidydns.ZoneInfo, hostname string) *tidydns.ZoneInfo {
	var zone *tidydns.ZoneInfo
	for _, z := range zones {
		if strings.HasSuffix(hostname, z.Name) {
			if zone == nil || len(z.Name) > len(zone.Name) {
				zone = z
			}
		}
	}
	return zone
}

// convertRecordType translates the text record type into Tidy constants
func convertRecordType(rType string) tidydns.RecordType {
	switch rType {
	case "A":
		return tidydns.RecordTypeA
	case "CNAME":
		return tidydns.RecordTypeCNAME
	case "TXT":
		return tidydns.RecordTypeTXT
	default:
		return tidydns.RecordType(-1)
	}
}

// createRecordInfo creates record info structures from endpoint
func createRecordInfo(e *endpoint.Endpoint, zone string) []tidydns.RecordInfo {
	rType := convertRecordType(e.RecordType)

	dnsName := strings.TrimSuffix(strings.TrimSuffix(e.DNSName, zone), ".")
	if len(dnsName) == 0 {
		dnsName = "."
	}

	records := make([]tidydns.RecordInfo, 0)
	for _, ta := range e.Targets {
		if rType == tidydns.RecordTypeTXT {
			ta = strings.TrimSuffix(strings.TrimPrefix(ta, "\""), "\"")
		}
		r := tidydns.RecordInfo{
			Name:        dnsName,
			Destination: ta,
			Type:        rType,
			TTL:         int(e.RecordTTL),
			Description: e.SetIdentifier,
		}
		records = append(records, r)
	}

	return records
}
