package did

// ProtocolOperation info.
type ProtocolOperation struct {
	// Operation is operation request.
	Operation string `json:"operation,omitempty"`
	// ProtocolVersion is protocol version.
	ProtocolVersion int `json:"protocolVersion,omitempty"`
	// TransactionNumber is transaction number.
	TransactionNumber int `json:"transactionNumber,omitempty"`
	// TransactionTime is transaction time.
	TransactionTime int64 `json:"transactionTime,omitempty"`
	// Type is type of operation.
	Type string `json:"type,omitempty"`
	// AnchorOrigin is anchor origin.
	AnchorOrigin string `json:"anchorOrigin,omitempty"`
	// CanonicalReference is canonical reference
	CanonicalReference string `json:"canonicalReference,omitempty"`
	// EquivalentReferences is equivalent references
	EquivalentReferences []string `json:"equivalentReferences,omitempty"`
}

type MethodMetadata struct {
	// UpdateCommitment is update commitment key.
	UpdateCommitment string `json:"updateCommitment,omitempty"`
	// RecoveryCommitment is recovery commitment key.
	RecoveryCommitment string `json:"recoveryCommitment,omitempty"`
	// Published is published key.
	Published bool `json:"published,omitempty"`
	// AnchorOrigin is anchor origin.
	AnchorOrigin string `json:"anchorOrigin,omitempty"`
	// UnpublishedOperations unpublished operations
	UnpublishedOperations []*ProtocolOperation `json:"unpublishedOperations,omitempty"`
	// PublishedOperations published operations
	PublishedOperations []*ProtocolOperation `json:"publishedOperations,omitempty"`
}

type DocumentMetadata struct {
	VersionID    string          `json:"versionId,omitempty"`
	Deactivated  bool            `json:"deactivated,omitempty"`
	CanonicalID  string          `json:"canonicalId,omitempty"`
	EquivalentID []string        `json:"equivalentId,omitempty"`
	Method       *MethodMetadata `json:"method,omitempty"`
}
