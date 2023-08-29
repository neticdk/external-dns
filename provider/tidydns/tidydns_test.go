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
	"os"
	"testing"

	"github.com/neticdk/tidydns-go/pkg/tidydns"
	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

func TestNewTidyDNSProvider(t *testing.T) {
	_ = os.Setenv("TIDYDNS_USER", "user")
	_ = os.Setenv("TIDYDNS_PASS", "pass")
	_, err := NewTidyDNSProvider(endpoint.NewDomainFilter([]string{"tidydns.com"}), provider.NewZoneIDFilter([]string{"1234"}), "endpoint", true)
	assert.NoError(t, err)

	_ = os.Unsetenv("TIDYDNS_USER")
	_ = os.Unsetenv("TIDYDNS_PASS")
	_, err = NewTidyDNSProvider(endpoint.NewDomainFilter([]string{"tidydns.com"}), provider.NewZoneIDFilter([]string{"1234"}), "endpoint", true)
	assert.Error(t, err)
}

func TestTidyDNSRecords(t *testing.T) {
	client := &mockClient{}
	client.On("ListZones", mock.AnythingOfType("*context.emptyCtx")).Return(zones, nil)
	client.On("ListRecords", mock.AnythingOfType("*context.emptyCtx"), 1).Return(zone1, nil)
	client.On("ListRecords", mock.AnythingOfType("*context.emptyCtx"), 2).Return(zone2, nil)

	provider := &tidyDNSProvider{
		client: client,
	}
	recs, err := provider.Records(context.Background())
	assert.NoError(t, err)
	assert.Len(t, recs, 3)
	client.AssertExpectations(t)
}

func TestTidyDNSApplyChanges(t *testing.T) {
	log.SetLevel(log.TraceLevel)

	client := &mockClient{}
	client.On("ListZones", mock.AnythingOfType("*context.emptyCtx")).Return(zones, nil)
	client.On("FindRecord", mock.AnythingOfType("*context.emptyCtx"), 1, "ttl", tidydns.RecordTypeA).Return(ttl, nil)
	client.On("FindRecord", mock.AnythingOfType("*context.emptyCtx"), 1, "regular3", tidydns.RecordTypeA).Return(regular3, nil)
	client.On("FindRecord", mock.AnythingOfType("*context.emptyCtx"), 1, "regular4", tidydns.RecordTypeA).Return(regular4, nil)
	client.On("FindRecord", mock.AnythingOfType("*context.emptyCtx"), 1, "regular5", tidydns.RecordTypeA).Return(regular5, nil)
	client.On("CreateRecord", mock.AnythingOfType("*context.emptyCtx"), 1, tidydns.RecordInfo{ID: 0, Type: 0, Name: "regular1", Description: "", Destination: "1.1.1.1", TTL: 0, Status: 0, Location: 0}).Return(1, nil)
	client.On("CreateRecord", mock.AnythingOfType("*context.emptyCtx"), 1, tidydns.RecordInfo{ID: 0, Type: 0, Name: "ttl", Description: "", Destination: "1.1.1.1", TTL: 100, Status: 0, Location: 0}).Return(2, nil)
	client.On("CreateRecord", mock.AnythingOfType("*context.emptyCtx"), 1, tidydns.RecordInfo{ID: 0, Type: 0, Name: "regular2", Description: "", Destination: "1.1.1.2", TTL: 0, Status: 0, Location: 0}).Return(3, nil)
	client.On("UpdateRecord", mock.AnythingOfType("*context.emptyCtx"), 1, 3, tidydns.RecordInfo{ID: 0, Type: 0, Name: "regular3", Description: "", Destination: "1.1.2.2", TTL: 100, Status: 0, Location: 0}).Return(nil)
	client.On("UpdateRecord", mock.AnythingOfType("*context.emptyCtx"), 1, 4, tidydns.RecordInfo{ID: 0, Type: 0, Name: "regular4", Description: "", Destination: "1.1.2.2", TTL: 100, Status: 0, Location: 0}).Return(nil)
	client.On("DeleteRecord", mock.AnythingOfType("*context.emptyCtx"), 1, 5).Return(nil)
	client.On("DeleteRecord", mock.AnythingOfType("*context.emptyCtx"), 1, 42).Return(nil)

	provider := &tidyDNSProvider{
		client: client,
		dryRun: false,
	}

	changes := &plan.Changes{}
	changes.Create = []*endpoint.Endpoint{
		{DNSName: "regular1.tidydns1.com", Targets: endpoint.Targets{"1.1.1.1"}, RecordType: "A"},
		{DNSName: "ttl.tidydns1.com", Targets: endpoint.Targets{"1.1.1.1"}, RecordType: "A", RecordTTL: 100},
		{DNSName: "regular2.tidydns1.com", Targets: endpoint.Targets{"1.1.1.2"}, RecordType: "A"},
	}
	changes.UpdateOld = []*endpoint.Endpoint{
		{DNSName: "regular3.tidydns1.com", Targets: endpoint.Targets{"127.0.3.1"}, RecordType: "A"},
		{DNSName: "regular4.tidydns1.com", Targets: endpoint.Targets{"127.0.4.1"}, RecordType: "A"},
	}
	changes.UpdateNew = []*endpoint.Endpoint{
		{DNSName: "regular3.tidydns1.com", Targets: endpoint.Targets{"1.1.2.2"}, RecordType: "A", RecordTTL: 100},
		{DNSName: "regular4.tidydns1.com", Targets: endpoint.Targets{"1.1.2.2"}, RecordType: "A", RecordTTL: 100},
	}
	changes.Delete = []*endpoint.Endpoint{
		{DNSName: "regular5.tidydns1.com", Targets: endpoint.Targets{"1.1.2.2"}, RecordType: "A", RecordTTL: 100},
		{DNSName: "ttl.tidydns1.com", Targets: endpoint.Targets{"1.1.1.1"}, RecordType: "A", RecordTTL: 100},
	}

	err := provider.ApplyChanges(context.Background(), changes)
	assert.NoError(t, err)
	client.AssertExpectations(t)
}

type mockClient struct {
	mock.Mock
}

var (
	zones = []*tidydns.ZoneInfo{
		{
			ID:   1,
			Name: "tidydns1.com",
		},
		{
			ID:   2,
			Name: "tidydns2.com",
		},
	}

	zone1 = []*tidydns.RecordInfo{
		{
			ID:          11,
			Type:        tidydns.RecordTypeA,
			Name:        "tidy11",
			Destination: "127.0.1.1",
		},
		{
			ID:          11,
			Type:        tidydns.RecordTypeTXT,
			Name:        "tidy11",
			Destination: "\"heritage=external-dns,external-dns/owner=prod1,external-dns/resource=ingress/namesapce/ingress1\"",
		},
	}

	zone2 = []*tidydns.RecordInfo{
		{
			ID:          21,
			Type:        tidydns.RecordTypeA,
			Name:        "tidy21",
			Destination: "127.0.2.1",
		},
	}

	ttl = []*tidydns.RecordInfo{
		{
			ID:          42,
			Type:        tidydns.RecordTypeA,
			Name:        "ttl",
			Destination: "1.1.1.1",
		},
	}
	regular3 = []*tidydns.RecordInfo{
		{
			ID:          3,
			Type:        tidydns.RecordTypeA,
			Name:        "regular3",
			Destination: "127.0.3.1",
		},
	}
	regular4 = []*tidydns.RecordInfo{
		{
			ID:          4,
			Type:        tidydns.RecordTypeA,
			Name:        "regular4",
			Destination: "127.0.4.1",
		},
	}
	regular5 = []*tidydns.RecordInfo{
		{
			ID:          5,
			Type:        tidydns.RecordTypeA,
			Name:        "regular5",
			Destination: "1.1.2.2",
		},
	}
)

func (m *mockClient) ListZones(ctx context.Context) ([]*tidydns.ZoneInfo, error) {
	args := m.Called(ctx)
	return args.Get(0).([]*tidydns.ZoneInfo), args.Error(1)
}

func (*mockClient) FindZoneID(ctx context.Context, name string) (int, error) {
	return 0, nil
}

func (m *mockClient) CreateRecord(ctx context.Context, zoneID int, info tidydns.RecordInfo) (int, error) {
	args := m.Called(ctx, zoneID, info)
	return args.Int(0), args.Error(1)
}

func (m *mockClient) UpdateRecord(ctx context.Context, zoneID int, recordID int, info tidydns.RecordInfo) error {
	args := m.Called(ctx, zoneID, recordID, info)
	return args.Error(0)
}

func (m *mockClient) ReadRecord(ctx context.Context, zoneID int, recordID int) (*tidydns.RecordInfo, error) {
	args := m.Called(ctx, zoneID, recordID)
	if args.Get(0) != nil {
		return args.Get(0).(*tidydns.RecordInfo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockClient) FindRecord(ctx context.Context, zoneID int, name string, rType tidydns.RecordType) ([]*tidydns.RecordInfo, error) {
	args := m.Called(ctx, zoneID, name, rType)
	if args.Get(0) != nil {
		return args.Get(0).([]*tidydns.RecordInfo), args.Error(1)
	}
	return nil, args.Error(1)
}

func (m *mockClient) ListRecords(ctx context.Context, zoneID int) ([]*tidydns.RecordInfo, error) {
	args := m.Called(ctx, zoneID)
	return args.Get(0).([]*tidydns.RecordInfo), args.Error(1)
}

func (m *mockClient) DeleteRecord(ctx context.Context, zoneID int, recordID int) error {
	args := m.Called(ctx, zoneID, recordID)
	return args.Error(0)
}
