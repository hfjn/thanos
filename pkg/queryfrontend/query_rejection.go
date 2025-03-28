package queryfrontend

import (
	"github.com/cespare/xxhash/v2"
	"github.com/efficientgo/core/errors"
	"github.com/go-kit/log"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/prometheus/promql/parser"
	"github.com/weaveworks/common/httpgrpc"
	"gopkg.in/yaml.v2"
	"net/http"
	"regexp"
)

const QueryRejectErrorMessage = "This query has been rejected by the query frontend."

var errCompilingQueryRejectionRegex = errors.New("error compiling query rejection regex")

type QueryRejection struct {
	Enabled                     bool             `yaml:"enabled" json:"enabled"`
	QueryAttributes             []queryAtrribute `yaml:"query_attributes" json:"query_attributes" doc:"nocli|description=List of query_attributes to match and reject queries. A query is rejected if it matches any query_attribute in this list. Each query_attribute has several properties (e.g., regex, time_window, user_agent), and all specified properties must match for a query_attribute to be considered a match. Only the specified properties are checked, and an AND operator is applied to them."`
	queryAttributeRegexHash     uint64
	queryAttributeCompiledRegex map[string]*regexp.Regexp
}

type queryAtrribute struct {
	ApiType                string `yaml:"api_type" json:"api_type" doc:"nocli|description=API type for the query. Should be one of the query, query_range, series, labels, label_values. If not set, it won't be checked."`
	Regex                  string `yaml:"regex" json:"regex" doc:"nocli|description=Regex that the query string (or at least one of the matchers in metadata query) should match. If not set, it won't be checked."`
	UserAgentRegex         string `yaml:"user_agent_regex" json:"user_agent_regex" doc:"nocli|description=Regex that User-Agent header of the request should match. If not set, it won't be checked."`
	CompiledRegex          *regexp.Regexp
	CompiledUserAgentRegex *regexp.Regexp
}

func checkForQueryRejection(r *http.Request, config QueryRejection, rejectedQueries *prometheus.CounterVec) error {
	if !config.Enabled {
		return nil
	}
	op := getOperation(r)
	if op == instantQueryOp || op == rangeQueryOp {
		query := r.FormValue("query")
		_, err := parser.ParseExpr(query)
		if err != nil {
			return httpgrpc.Errorf(http.StatusBadRequest, "%s", err.Error())
		}
		if config.Enabled && query != "" {
			for _, attribute := range config.QueryAttributes {
				if matchAttributeForExpressionQuery(attribute, op, r, query) {
					rejectedQueries.WithLabelValues(op).Inc()
					return httpgrpc.Errorf(http.StatusUnprocessableEntity, QueryRejectErrorMessage)
				}
			}
		}
	}

	if config.Enabled && (op == seriesOp || op == labelNamesOp || op == labelValuesOp) {
		for _, attribute := range config.QueryAttributes {
			if matchAttributeForMetadataQuery(attribute, op, r) {
				rejectedQueries.WithLabelValues(op).Inc()
				return httpgrpc.Errorf(http.StatusUnprocessableEntity, QueryRejectErrorMessage)
			}
		}
	}

	return nil
}

func matchAttributeForExpressionQuery(attribute queryAtrribute, op string, r *http.Request, query string) bool {
	matched := false
	if attribute.ApiType != "" {
		matched = true
		if attribute.ApiType != op {
			return false
		}
	}
	if attribute.Regex != "" {
		matched = true
		if attribute.Regex != ".*" && attribute.Regex != ".+" && attribute.CompiledRegex != nil && !attribute.CompiledRegex.MatchString(query) {
			return false
		}
	}

	if attribute.UserAgentRegex != "" {
		matched = true
		if attribute.UserAgentRegex != ".*" && attribute.CompiledUserAgentRegex != nil && !attribute.CompiledUserAgentRegex.MatchString(r.Header.Get("User-Agent")) {
			return false
		}
	}

	return matched
}

func matchAttributeForMetadataQuery(attribute queryAtrribute, op string, r *http.Request) bool {
	matched := false
	if attribute.ApiType != "" {
		matched = true
		if attribute.ApiType != op {
			return false
		}
	}
	if err := r.ParseForm(); err != nil {
		return false
	}
	if attribute.Regex != "" {
		matched = true
		if attribute.Regex != ".*" && attribute.CompiledRegex != nil {
			atLeastOneMatched := false
			for _, matcher := range r.Form["match[]"] {
				if attribute.CompiledRegex.MatchString(matcher) {
					atLeastOneMatched = true
					break
				}
			}
			if !atLeastOneMatched {
				return false
			}
		}
	}

	if attribute.UserAgentRegex != "" {
		matched = true
		if attribute.UserAgentRegex != ".*" && attribute.CompiledUserAgentRegex != nil && !attribute.CompiledUserAgentRegex.MatchString(r.Header.Get("User-Agent")) {
			return false
		}
	}

	return matched
}

func NewQueryRejectionConfig(logger log.Logger, confContentYaml []byte) (*QueryRejection, error) {
	queryRejectionConfig := &QueryRejection{}
	if err := yaml.UnmarshalStrict(confContentYaml, queryRejectionConfig); err != nil {
		return nil, errors.Wrap(err, "parsing config YAML file")
	}
	if err := queryRejectionConfig.compileQueryAttributeRegex(); err != nil {
		return nil, err
	}
	return queryRejectionConfig, nil
}

func (l *QueryRejection) hasQueryAttributeRegexChanged() bool {
	var newHash uint64
	h := xxhash.New()

	if l.Enabled {
		for _, attribute := range l.QueryAttributes {
			addToHash(h, attribute.Regex)
			addToHash(h, attribute.UserAgentRegex)
		}
	}

	newHash = h.Sum64()

	if newHash != l.queryAttributeRegexHash {
		l.queryAttributeRegexHash = newHash
		return true
	}
	return false
}

func addToHash(h *xxhash.Digest, regex string) {
	if regex == "" {
		return
	}
	_, _ = h.WriteString(regex)
	_, _ = h.Write([]byte{'\xff'})
}

func (l *QueryRejection) compileQueryAttributeRegex() error {
	if !l.Enabled {
		return nil
	}
	regexChanged := l.hasQueryAttributeRegexChanged()
	newCompiledRegex := map[string]*regexp.Regexp{}

	if l.Enabled {
		err := l.compileQueryAttributeRegexes(l.QueryAttributes, regexChanged, newCompiledRegex)
		if err != nil {
			return err
		}
	}

	if regexChanged {
		l.queryAttributeCompiledRegex = newCompiledRegex
	}

	return nil
}

func (l *QueryRejection) compileQueryAttributeRegexes(queryAttributes []queryAtrribute, regexChanged bool, newCompiledRegex map[string]*regexp.Regexp) error {
	for j, attribute := range queryAttributes {
		if regexChanged {
			compiledRegex, err := regexp.Compile(attribute.Regex)
			if err != nil {
				return errors.Wrap(err, "Error compiling regex")
			}
			newCompiledRegex[attribute.Regex] = compiledRegex
			queryAttributes[j].CompiledRegex = compiledRegex

			compiledUserAgentRegex, err := regexp.Compile(attribute.UserAgentRegex)
			if err != nil {
				return errors.Wrap(err, "Error compiling user agent regex")
			}
			newCompiledRegex[attribute.UserAgentRegex] = compiledUserAgentRegex
			queryAttributes[j].CompiledUserAgentRegex = compiledUserAgentRegex
		} else {
			queryAttributes[j].CompiledRegex = l.queryAttributeCompiledRegex[attribute.Regex]
			queryAttributes[j].CompiledUserAgentRegex = l.queryAttributeCompiledRegex[attribute.UserAgentRegex]
		}
	}
	return nil
}
