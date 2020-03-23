package jsonapi-params-decode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/manyminds/api2go"
)

// contextKey type used for access to context's values
// TODO: use function inside pkg instead configurable contextKey
type contextKey uint8

// list of used context's keys
const (
	paramsKey contextKey = iota
)

type decoder struct {
	prefix             string
	defaultContentType string
}

// Params represents jsonapicrud request params
type Params struct {
	ResourceName string
	ID           string

	Sort []string

	// // ?fields[geoip]=geohash,time_zone => {geoip:[geohash,time_zone]}
	// Fields map[string][]string

	// ?include=field_name,field_name.nested_field_name => [author, comments.author]
	Include []string

	// Filters cleanups the result and remains resources which satisfy criteria
	// ?filter[field_name.nested_field_name][predicator]=value
	Filters []Filter

	// paggination
	PageSize   uint64
	PageNumber uint64
	PageOffset uint64
	PageLimit  uint64
}

// Pred represents filter's predicate
type Pred uint8

// Available Preds
const (
	PredUndefined Pred = iota // PredUndefined - for errors
	PredEqual                 // the field is equal one of provided values
	PredNotEqual
	PredGreterThan
	PredLessThan
	PredGreterOrEqual
	PredLessOrEqual
	PredExists
	PredContains    // the field contains whole provided value
	PredNotContains // the field must not contains whole provided value
	PredHasPreffix  // starts with provided value
	PredHasSuffix   // ends with provided value
	// PredSame          // same - means field same like other field
)

// Filter represents separated part of filtration
type Filter struct {
	Relation string // should be empty if filter applied to self
	Field    string
	Pred     Pred
	Value    interface{}
}

// NewParamsDecoder - middleware for decoding jsonapi params to struct
func NewParamsDecoder(prefix string, defaultContentType string) func(http.Handler) http.Handler {

	dec := &decoder{prefix: prefix, defaultContentType: defaultContentType}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			params, err := dec.decode(r)
			if err != nil {
				dec.HandleHTTPError(err, w, 400)
				return
			}
			ctx := context.WithValue(r.Context(), paramsKey, params)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// ParamsFromContext returns Params
func ParamsFromContext(ctx context.Context) (*Params, error) {
	params, ok := ctx.Value(paramsKey).(*Params)
	var err error
	if !ok {
		err = errors.New("decoder middleware not configured")
	}
	return params, err
}

// HandleHTTPError .
func (d *decoder) HandleHTTPError(err error, w http.ResponseWriter, code int) {
	payload := api2go.NewHTTPError(err, err.Error(), code)

	// if error already serialized - use that error without modifications (it contains not exportet fields)
	if e, ok := err.(api2go.HTTPError); ok {
		payload = e
	}

	// if Errors are not specified, display error's message
	if len(payload.Errors) == 0 {
		payload.Errors = []api2go.Error{{Title: err.Error(), Status: strconv.Itoa(code)}}
	}

	w.Header().Set("Content-Type", d.defaultContentType)
	w.WriteHeader(code)
	if err := json.NewEncoder(w).Encode(payload); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (d *decoder) decode(r *http.Request) (*Params, error) {
	p := &Params{}

	err := d.decodePath(r.URL.EscapedPath(), p)
	if err != nil {
		return p, err
	}

	values := r.URL.Query()
	err = d.decodePage(values, p)
	if err != nil {
		return p, err
	}

	err = d.decodeInclude(values, p)
	if err != nil {
		return p, err
	}

	err = d.decodeSort(values, p)
	if err != nil {
		return p, err
	}

	err = d.decodeFilter(values, p)
	if err != nil {
		return p, err
	}

	return p, nil
}

func (d *decoder) decodePage(values url.Values, p *Params) error {
	pageSizeParam := values.Get("page[size]")
	if pageSizeParam != "" {
		pageSize, err := strconv.ParseUint(pageSizeParam, 10, 64)
		if err != nil {
			return err
		}
		p.PageSize = pageSize
	}

	pageLimitParam := values.Get("page[limit]")
	if pageLimitParam != "" {
		pageLimit, err := strconv.ParseUint(pageLimitParam, 10, 64)
		if err != nil {
			return err
		}
		p.PageLimit = pageLimit
	}

	pageNumberParam := values.Get("page[number]")
	if pageNumberParam != "" {
		pageNumber, err := strconv.ParseUint(pageNumberParam, 10, 64)
		if err != nil {
			return err
		}
		p.PageNumber = pageNumber
	}

	pageOffsetParam := values.Get("page[offset]")
	if pageOffsetParam != "" {
		pageOffset, err := strconv.ParseUint(pageOffsetParam, 10, 64)
		if err != nil {
			return err
		}
		p.PageOffset = pageOffset
	}

	if p.PageSize != 0 || p.PageLimit != 0 || p.PageNumber != 0 || p.PageOffset != 0 { // validate only if someane is exists

		// can choose strategy
		if p.PageLimit > 0 && p.PageSize > 0 { // both active
			return fmt.Errorf("page[size] and page[limit] are non zero (%d, %d), they can't be used together", p.PageSize, p.PageLimit)
		}
		if p.PageLimit <= 0 && p.PageSize <= 0 { // both inactive
			return fmt.Errorf("page[size] or page[limit] must be grater than zero")
		}

		// page-based
		// number must be > 0
		if p.PageSize > 0 {
			if p.PageNumber <= 0 {
				return fmt.Errorf("page[number] must be grater than zero")
			}

			if p.PageOffset > 0 {
				return fmt.Errorf("page[offset] can't be used with bage-based paggination")
			}
		}

		// limit-based
		// offset must be >= 0
		if p.PageLimit > 0 {
			if p.PageOffset < 0 {
				return fmt.Errorf("page[offset] must be grater or equal than zero")
			}

			if p.PageNumber > 0 {
				return fmt.Errorf("page[number] can't be used with limit-based paggination")
			}
		}
	}

	return nil
}

func (d *decoder) decodeInclude(values url.Values, p *Params) error {
	includeParam := values.Get("include")

	if includeParam != "" {
		include := strings.Split(includeParam, ",")
		p.Include = include
	}

	return nil
}

func (d *decoder) decodeSort(values url.Values, p *Params) error {
	sortParam := values.Get("sort")

	if sortParam != "" {
		sort := strings.Split(sortParam, ",")
		p.Sort = sort
	}

	return nil
}

// decodePath extract ResourceName and ID from path
func (d *decoder) decodePath(escapedPath string, p *Params) error {
	escapedPath = strings.TrimLeft(escapedPath, d.prefix)
	parts := strings.Split(escapedPath, "/")

	// filter empty elements
	filtered := parts[:0]
	for _, x := range parts {
		if x != "" {
			filtered = append(filtered, x)
		}
	}

	// TODO implement relationships
	switch len(filtered) {
	case 1:
		p.ResourceName = filtered[0]
	case 2:
		p.ResourceName = filtered[0]
		p.ID = filtered[1]
	}

	return nil
}

func (d *decoder) decodeFilter(values url.Values, p *Params) error {
	filtersByResource := parseParamToMapMap("filter", values)
	p.Filters = make([]Filter, 0)

	for field, valuesByPred := range filtersByResource {
		// empty resource name means Params.ResourceName
		resource := ""

		// if field contains dot `.` - it is relation field
		if strings.Contains(field, ".") {
			resource = field[:strings.IndexByte(field, '.')]
			field = field[strings.IndexByte(field, '.')+1:]
		}

		for predStr, val := range valuesByPred {
			pred, err := predByStr(predStr)
			if err != nil {
				return err
			}

			filter := Filter{
				Relation: resource,
				Field:    field,
				Pred:     pred,
				Value:    val,
			}
			p.Filters = append(p.Filters, filter)
		}
	}
	return nil
}

func predByStr(str string) (Pred, error) {
	switch str {
	case "eq":
		return PredEqual, nil
	case "ne":
		return PredNotEqual, nil
	case "gt":
		return PredGreterThan, nil
	case "lt":
		return PredLessThan, nil
	case "ge":
		return PredGreterOrEqual, nil
	case "le":
		return PredLessOrEqual, nil
	case "contains":
		return PredContains, nil
	case "exists":
		return PredExists, nil
	case "not-contains":
		return PredNotContains, nil
	case "starts":
		return PredHasPreffix, nil
	case "ends":
		return PredHasSuffix, nil
	default:
		return PredUndefined, fmt.Errorf("can't parse predicate %s", str)
	}
}

// func (d *decoder) decodeFields(values url.Values, p *Params) error {
// 	filtersByResource := parseParamToMap("filter", values)
// 	p.Filters = make(map[string][]Filter, 0)
// 	for field, parsedValues := range filtersByResource {
// 		// empty resource name means Params.ResourceName
// 		resource := ""

// 		// if field contains dot `.` - it is relation field
// 		if strings.Contains(field, ".") {
// 			resource = field[:strings.IndexByte(field, '.')]
// 			field = field[strings.IndexByte(field, '.')+1:]
// 		}

// filter := Filter{
// 	Field: field,
// 	Pred:  PredEq,
// 	Value: parsedValues,
// }

// 		p.Filters[resource] = append(p.Filters[resource], filter)
// 	}
// 	spew.Dump(filtersByResource)
// 	spew.Dump(p.Filters)
// 	return nil
// }

// parseParamToMapMap returns map of nested params
// params `?{name}[k1][in]=v1,v2&{name}[relation.k2][eq]=v3&{name}[k1][ne]=v4`
// converts to `{
//   "k1": {
//     "in": ["v1", "v2"],
//     "ne": ["v4"]
//   },
//   "relation.k2": {
//     "eq": ["v3"]
//   }
// }`

func parseParamToMapMap(name string, keyValues url.Values) map[string]map[string][]string {
	result := make(map[string]map[string][]string, 0)

	for key, values := range keyValues {
		// param must be serialized in URL as map of maps
		if strings.Count(key, "[") != 2 || strings.Count(key, "]") != 2 {
			continue
		}

		// parse only {name}[...] params
		base := key[:strings.IndexByte(key, '[')]
		if base != name {
			continue
		}

		// get resourceName from URL param's name
		resourceName := key[strings.IndexByte(key, '[')+1 : strings.IndexByte(key, ']')]
		if _, ok := result[resourceName]; !ok {
			result[resourceName] = make(map[string][]string, 0)
		}

		// get second level names
		secondRemainder := key[strings.IndexByte(key, ']')+2:]
		second := secondRemainder[:len(secondRemainder)-1]
		if _, ok := result[resourceName][second]; !ok {
			result[resourceName][second] = make([]string, 0)
		}

		// iterate over all values and put in to {name}[resourceName][second]
		for _, value := range values {
			for _, fieldName := range strings.Split(value, ",") {
				result[resourceName][second] = append(result[resourceName][second], fieldName)
			}
		}
	}

	return result
}

// parseParamToMap returns map of nested params
// params `?{name}[k1]=v1,v2&{name}[relation.k2]=v3&{name}[k1]=v4`
// converts to `{"k1":["v1", "v2", "v4"], "relation.k2":["v3"]}`
func parseParamToMap(name string, keyValues url.Values) map[string][]string {
	result := make(map[string][]string, 0)

	for key, values := range keyValues {
		// param must be serialized in URL as map
		if !strings.Contains(key, "[") || !strings.Contains(key, "]") {
			continue
		}

		// parse only {name}[...] params
		base := key[:strings.IndexByte(key, '[')]
		if base != name {
			continue
		}

		// get resourceName from URL param's name
		resourceName := key[strings.IndexByte(key, '[')+1 : strings.IndexByte(key, ']')]
		if _, ok := result[resourceName]; !ok {
			result[resourceName] = make([]string, 0)
		}

		// iterate over all {name}[resourceName] values
		for _, value := range values {
			for _, fieldName := range strings.Split(value, ",") {
				result[resourceName] = append(result[resourceName], fieldName)
			}
		}
	}

	return result
}

// TODO: parse filters, sparse fields etc

// func MakeFilters(r Request) (filters map[string]ResourceFilter, err error) {
// 	filters = map[string]ResourceFilter{}
// 	filterQuery := r.GetMap("filter")
// 	for k, value := range filterQuery {
// 		index := strings.LastIndex(k, ".")
// 		filter := ""
// 		key := ""
// 		if index != -1 {
// 			filter = k[:index]
// 			key = k[index+1:]
// 		} else {
// 			key = k
// 		}

// 		if _, ok := filters[filter]; !ok {
// 			filters[filter] = ResourceFilter{}
// 		}
// 		filters[filter][key] = value
// 	}
// 	return
// }

// // ParseFields - parses URL and returns fields indexed by resource
// // ?fields[geoip]=geohash,time_zone => {geoip:[geohash,time_zone]}
// func ParseFields(r *http.Request) map[string][]string {
// 	result := make(map[string][]string, 0)

// 	keyValues := r.URL.Query()
// for key, values := range keyValues {
// 	// fields must by serialized in URL as structure
// 	if !strings.Contains(key, "[") || !strings.Contains(key, "]") {
// 		continue
// 	}

// 	// parse only fields[...] params
// 	base := key[:strings.IndexByte(key, '[')]
// 	if base != "fields" {
// 		continue
// 	}

// 	// get resourceName from URL param's name
// 	resourceName := key[strings.IndexByte(key, '[')+1 : strings.IndexByte(key, ']')]
// 	if _, ok := result[resourceName]; !ok {
// 		result[resourceName] = make([]string, 0)
// 	}

// 	// iterate over all fields[resourceName] values
// 	for _, value := range values {
// 		for _, fieldName := range strings.Split(value, ",") {
// 			result[resourceName] = append(result[resourceName], fieldName)
// 		}
// 	}
// }

// 	return result
// }
