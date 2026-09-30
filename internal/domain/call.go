package domain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"time"
)

// Tool call rules (DD-08 §3): a call is tracked before anything is sent,
// admitted by Control's single-use AdmitTool, sent at most once after its
// send marker is committed, and never sent again: the same command answers
// the original call, and an uncertain send stays UNKNOWN until its
// original identity is reconciled.

// CallState mirrors CallState of anvilkit.mcp.v1 and the state column.
type CallState string

const (
	CallAccepted  CallState = "accepted"
	CallAdmitted  CallState = "admitted"
	CallSent      CallState = "sent"
	CallSucceeded CallState = "succeeded"
	CallFailed    CallState = "failed"
	CallDenied    CallState = "denied"
	CallUnknown   CallState = "unknown"
	CallCanceled  CallState = "canceled"
)

// Failure codes of calls.
const (
	CallGrantNotExecutable  = "GRANT_NOT_EXECUTABLE"
	CallRecoveryRestricted  = "RECOVERY_RESTRICTED"
	CallRouteUnqualified    = "PROFILE_UNQUALIFIED"
	CallProtocolMismatch    = "PROTOCOL_MISMATCH"
	CallSchemaDrift         = "SCHEMA_DRIFT"
	CallAuthorization       = "AUTHORIZATION_SUBSTITUTED"
	CallEgressRefused       = "EGRESS_REFUSED"
	CallUpstreamUnavailable = "UPSTREAM_UNAVAILABLE"
	CallNotSent             = "SEND_NOT_ATTEMPTED"
	CallToolError           = "TOOL_ERROR"
	CallProtocolError       = "UPSTREAM_REFUSED"
	CallOutcomeUnknown      = "OUTCOME_UNKNOWN"
	CallResultTooLarge      = "RESULT_TOO_LARGE"
)

// Call is one tracked tool request.
type Call struct {
	CallID             string
	TenantID           string
	GrantID            string
	GrantRevision      uint64
	ServerID           string
	DescriptorRevision uint64
	DescriptorDigest   string
	ProtocolVersion    string
	Transport          string
	Route              string
	Method             string
	SideEffecting      bool
	Exposure           Money
	ArgumentRef        string
	ArgumentDigest     string
	Arguments          []byte
	OperationID        string
	AttemptID          string
	InstanceID         string
	ExecutionEpoch     uint64
	State              CallState
	DispatchID         string
	FailureCode        string
	Result             []byte
	ResultDigest       string
	ResultRef          string
	UsageUnits         *uint64
	SendMarkerAt       *time.Time
	ObservedAt         *time.Time
	ObservationSeq     uint64
	CommandID          string
	RequestDigest      string
	Deadline           time.Time
	CreatedAt          time.Time
	UpdatedAt          time.Time
}

// Terminal reports whether the call's MCP state can no longer change.
func (c Call) Terminal() bool {
	switch c.State {
	case CallSucceeded, CallFailed, CallDenied, CallCanceled:
		return true
	}
	return false
}

// CallRequest is a CreateCall command's content.
type CallRequest struct {
	GrantID        string
	GrantRevision  uint64
	Method         string
	ArgumentRef    string
	ArgumentDigest string
	Arguments      []byte
	OperationID    string
	AttemptID      string
	InstanceID     string
	ExecutionEpoch uint64
	Deadline       time.Time
}

// CheckCallRequest validates what can be validated without state: the
// execution binding, the deadline, and the argument bytes — their digest
// and that they are one JSON object without duplicate keys.
func CheckCallRequest(r CallRequest, now time.Time) error {
	// The instance is optional: an execution without a physical instance
	// (an Activity) is admitted by Control without one; a Job's sidecar
	// always names its own.
	if r.OperationID == "" || r.AttemptID == "" || r.ExecutionEpoch == 0 {
		return fmt.Errorf("%w: a call names its operation, attempt and execution epoch", ErrInvalid)
	}
	if !r.Deadline.After(now) {
		return fmt.Errorf("%w: the call deadline has passed", ErrInvalid)
	}
	if DigestBytes(r.Arguments) != r.ArgumentDigest {
		return fmt.Errorf("%w: the arguments do not hash to argument_digest", ErrInvalid)
	}
	if err := checkObject(r.Arguments); err != nil {
		return fmt.Errorf("%w: arguments: %v", ErrInvalid, err)
	}
	return nil
}

// checkObject accepts exactly one JSON object whose objects never repeat a
// key (a duplicate key is read differently by different parsers).
func checkObject(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return fmt.Errorf("not a JSON object")
	}
	if err := walkObject(dec, 1); err != nil {
		return err
	}
	if _, err := dec.Token(); err != io.EOF {
		return fmt.Errorf("trailing data")
	}
	return nil
}

func walkObject(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("nested too deeply")
	}
	seen := map[string]bool{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		key, _ := tok.(string)
		if seen[key] {
			return fmt.Errorf("duplicate key %q", key)
		}
		seen[key] = true
		if err := walkValue(dec, depth); err != nil {
			return err
		}
	}
	_, err := dec.Token()
	return err
}

func walkValue(dec *json.Decoder, depth int) error {
	if depth > 64 {
		return fmt.Errorf("nested too deeply")
	}
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		return walkObject(dec, depth+1)
	case json.Delim('['):
		for dec.More() {
			if err := walkValue(dec, depth+1); err != nil {
				return err
			}
		}
		_, err := dec.Token()
		return err
	}
	return nil
}
