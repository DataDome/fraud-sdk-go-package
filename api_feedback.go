package fraudsdkgo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
)

// Feedback is the operation struct for Post /v1/feedback.
type Feedback struct {
	payload FeedbackPayload
}

// NewFeedback creates a new [Feedback] operation.
// Provide feedback about Account Protect recommendations for a specific event, account, or user.
func NewFeedback(decision FeedbackPayloadDecision, origin FeedbackPayloadOrigin, opts ...FeedbackPayloadOption) (*Feedback, error) {
	var payload FeedbackPayload
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt(&payload)
	}
	payload.Decision = decision
	payload.Origin = origin
	if payload.EventId == nil && payload.Account == nil && payload.UserId == nil {
		return nil, fmt.Errorf("at least one of eventId, account, userId must be set")
	}
	return &Feedback{payload: payload}, nil
}

// PerformOperation executes the [Feedback] operation.
func (o *Feedback) PerformOperation(ctx context.Context, c *Client, r *http.Request, rm *RequestMetadata) (*Feedback201Response, error) {
	endpoint := fmt.Sprintf("%s/v1/feedback", c.Endpoint)
	result, err := post[Feedback201Response](ctx, c, endpoint, &o.payload)
	if err != nil || result == nil {
		if err == nil {
			return nil, fmt.Errorf("unexpected empty response from API")
		}
		var httpErr *HTTPError
		if errors.As(err, &httpErr) {
			var apiErr Feedback400Response
			if json.Unmarshal(httpErr.Body, &apiErr) == nil {
				return nil, &apiErr
			}
		}
		return nil, err
	}
	return result, nil
}
