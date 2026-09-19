// Package control is the owner's client of Control's DispatchService for
// the original-dispatch query of an expired external-effect lease (DD-02
// §4, DD-09 §1). Only CONFIRMED_NOT_SENT or DENIED release the lease;
// every other state, answer or error leaves it unreleased.
package control

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	controlv1 "github.com/ancyloce/anvilkit-agent-contracts/go/anvilkit/control/v1"
	"github.com/ancyloce/anvilkit-agent-mcp/internal/domain"
)

// Owner is the dispatch owner identity this service presents (the sender
// recorded on MCP tool dispatches; DD-08).
const Owner = "anvilkit-agent-mcp"

type DispatchQuery struct {
	conn    *grpc.ClientConn
	client  controlv1.DispatchServiceClient
	timeout time.Duration
}

// Dial connects to Control (plaintext, DEVELOPMENT_ONLY; workload mTLS is
// ENV-03) without blocking; failures surface per query.
func Dial(address string, timeout time.Duration) (*DispatchQuery, error) {
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("control %s: %w", address, err)
	}
	return &DispatchQuery{conn: conn, client: controlv1.NewDispatchServiceClient(conn), timeout: timeout}, nil
}

func (d *DispatchQuery) Close() error { return d.conn.Close() }

func (d *DispatchQuery) Outcome(ctx context.Context, dispatchID string) (domain.DispatchOutcome, error) {
	ctx, cancel := context.WithTimeout(ctx, d.timeout)
	defer cancel()
	resp, err := d.client.GetDispatch(ctx, &controlv1.GetDispatchRequest{DispatchId: dispatchID, Owner: Owner})
	if err != nil {
		return domain.DispatchUnknown, err
	}
	switch resp.GetDispatch().GetState() {
	case controlv1.DispatchState_DISPATCH_STATE_CONFIRMED_NOT_SENT, controlv1.DispatchState_DISPATCH_STATE_DENIED:
		return domain.DispatchNotSent, nil
	case controlv1.DispatchState_DISPATCH_STATE_OBSERVED:
		return domain.DispatchSent, nil
	default:
		return domain.DispatchUnknown, nil
	}
}
