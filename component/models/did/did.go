package did

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type DID struct {
	Scheme           string
	Method           string
	MethodSpecificID string
}

func (d *DID) String() string {
	return fmt.Sprintf("%s:%s:%s", d.Scheme, d.Method, d.MethodSpecificID)
}

func Parse(did string) (*DID, error) {
	const idchar = `a-zA-Z0-9-_\.`
	regex := fmt.Sprintf(`^did:[a-z0-9]+:(:+|[:%s]+)*[%%:%s]+[^:]$`, idchar, idchar)

	r, err := regexp.Compile(regex)
	if err != nil {
		return nil, fmt.Errorf("failed to compile regex=%s (this should not have happened!). %w", regex, err)
	}

	if !r.MatchString(did) {
		return nil, fmt.Errorf("did:%s is not a valid did", did)
	}

	parts := strings.SplitN(did, ":", 3)

	return &DID{
		Scheme:           "did",
		Method:           parts[1],
		MethodSpecificID: parts[2],
	}, nil
}

type DIDURL struct {
	DID
	Path     string
	Queries  map[string][]string
	Fragment string
}

func ParseDIDURL(didURL string) (*DIDURL, error) {
	split := strings.IndexAny(didURL, "?/#")

	didPart := didURL
	pathQueryFragment := ""

	if split != -1 {
		didPart = didURL[:split]
		pathQueryFragment = didURL[split:]
	}

	retDID, err := Parse(didPart)
	if err != nil {
		return nil, err
	}

	if pathQueryFragment == "" {
		return &DIDURL{
			DID:     *retDID,
			Queries: map[string][]string{},
		}, nil
	}

	hasPath := pathQueryFragment[0] == '/'

	if !hasPath {
		pathQueryFragment = "/" + pathQueryFragment
	}

	urlParts, err := url.Parse(pathQueryFragment)
	if err != nil {
		return nil, fmt.Errorf("failed to parse path, query, and fragment compoments of DID URL: %w", err)
	}

	ret := &DIDURL{
		DID:      *retDID,
		Queries:  urlParts.Query(),
		Fragment: urlParts.Fragment,
	}

	if hasPath {
		ret.Path = urlParts.Path
	}

	return ret, nil
}
