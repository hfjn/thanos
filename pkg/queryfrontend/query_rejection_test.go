package queryfrontend

import (
	"fmt"
	"github.com/thanos-io/thanos/internal/cortex/querier/queryrange"
	"github.com/thanos-io/thanos/internal/cortex/util/validation"
	"net/http"
	"net/url"
	"regexp"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/weaveworks/common/httpgrpc"
)

var rejectedQueriesPerTenant = prometheus.NewCounterVec(prometheus.CounterOpts{}, []string{"op", "user"})

func Test_rejectQueryOrSetPriorityShouldReturnDefaultPriorityIfNotEnabledOrInvalidQueryString(t *testing.T) {

	limits := queryrange.mockLimits{
		QueryRejection: validation.QueryRejection{
			Enabled: false,
		},
	}

	type testCase struct {
		queryRejectionEnabled bool
		path                  string
		expectedError         error
	}

	tests := map[string]testCase{
		"should miss if query priority/rejection not enabled": {
			path: "/api/v1/query?time=1536716898&query=sum%28container_memory_rss%29+by+%28namespace%29",
		},
		"should throw parse error if query string empty": {
			queryRejectionEnabled: true,
			path:                  "/api/v1/query?time=1536716898&query=",
			expectedError:         httpgrpc.Errorf(http.StatusBadRequest, "unknown position: parse error: no expression found in input"),
		},
		"should do nothing if regex match and rejection disabled": {
			queryRejectionEnabled: false,
			path:                  "/api/v1/query?time=1536716898&query=sum%28container_memory_rss%29+by+%28namespace%29",
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("GET", testData.path, http.NoBody)
			require.NoError(t, err)
			limits.queryRejection.Enabled = testData.queryRejectionEnabled
			resultErr := checkForQueryRejection(req, limits, "", rejectedQueriesPerTenant)
			assert.Equal(t, testData.expectedError, resultErr)
		})
	}
}

func Test_rejectQueryOrSetPriorityShouldRejectIfMatches(t *testing.T) {
	now := time.Now()
	limits := queryrange.mockLimits{
		QueryRejection: validation.QueryRejection{
			Enabled:         false,
			QueryAttributes: []validation.QueryAttribute{},
		},
	}

	type testCase struct {
		queryRejectionEnabled bool
		path                  string
		expectedError         error
		expectedPriority      int64
		rejectQueryAttribute  validation.QueryAttribute
	}

	tests := map[string]testCase{

		"should not reject if query rejection not enabled": {
			queryRejectionEnabled: false,
			path:                  "/api/v1/query_range?start=1536716898&end=1536729898&step=7s&query=avg_over_time%28rate%28node_cpu_seconds_total%5B1m%5D%29%5B10m%3A5s%5D%29",
			expectedError:         nil,
			rejectQueryAttribute: validation.QueryAttribute{
				Regex:         ".*",
				CompiledRegex: regexp.MustCompile(".*"),
			},
		},

		"should reject if query rejection enabled with all query match regex": {
			queryRejectionEnabled: true,
			path:                  "/api/v1/query_range?start=1536716898&end=1536729898&step=7s&query=avg_over_time%28rate%28node_cpu_seconds_total%5B1m%5D%29%5B10m%3A5s%5D%29",
			expectedError:         httpgrpc.Errorf(http.StatusUnprocessableEntity, QueryRejectErrorMessage),
			rejectQueryAttribute: validation.QueryAttribute{
				Regex:         ".*",
				CompiledRegex: regexp.MustCompile(".*"),
			},
		},

		"should not reject if query api_type doesn't match matches": {
			queryRejectionEnabled: true,
			path:                  fmt.Sprintf("/api/v1/series?start=%d&end=%d&step=7s&match[]=%s", now.Add(-30*time.Minute).UnixMilli()/1000, now.Add(-20*time.Minute).UnixMilli()/1000, url.QueryEscape("count(sum(up))")),
			expectedError:         nil,
			rejectQueryAttribute: validation.QueryAttribute{
				ApiType:       "query",
				Regex:         ".*sum.*",
				CompiledRegex: regexp.MustCompile(".*sum.*"),
			},
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("GET", testData.path, http.NoBody)
			require.NoError(t, err)
			limits.queryRejection.Enabled = testData.queryRejectionEnabled
			limits.queryRejection.QueryAttributes = []validation.QueryAttribute{testData.rejectQueryAttribute}
			resultErr := checkForQueryRejection(req, limits, "", rejectedQueriesPerTenant)
			assert.Equal(t, testData.expectedError, resultErr)
		})
	}
}

func Test_matchAttributeForExpressionQueryShouldMatchRegex(t *testing.T) {
	queryAttribute := validation.QueryAttribute{}

	type testCase struct {
		regex  string
		query  string
		result bool
	}

	tests := map[string]testCase{
		"should hit if regex matches": {
			regex:  "(^sum|c(.+)t)",
			query:  "sum(up)",
			result: true,
		},
		"should miss if regex doesn't match": {
			regex: "(^sum|c(.+)t)",
			query: "min(up)",
		},
		"should hit if regex matches - .*": {
			regex:  ".*",
			query:  "count(sum(up))",
			result: true,
		},
		"should hit if regex matches - .+": {
			regex:  ".+",
			query:  "count(sum(up))",
			result: true,
		},
		"should hit if regex is an empty string": {
			regex:  "",
			query:  "sum(up)",
			result: true,
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			queryAttribute.Regex = testData.regex
			queryAttribute.CompiledRegex = regexp.MustCompile(testData.regex)
			priority := matchAttributeForExpressionQuery(queryAttribute, "query_range", &http.Request{}, testData.query)
			assert.Equal(t, testData.result, priority)
		})
	}

}

func Test_matchAttributeForExpressionQueryShouldMatchUserAgentRegex(t *testing.T) {

	type testCase struct {
		userAgentRegex  string
		userAgentHeader string
		result          bool
	}

	tests := map[string]testCase{
		"should hit if regex matches": {
			userAgentRegex:  "(^grafana-agent|prometheus-(.*)client(.+))",
			userAgentHeader: "prometheus-client-go/v0.9.3",
			result:          true,
		},
		"should miss if regex doesn't match": {
			userAgentRegex:  "(^grafana-agent|prometheus-(.*)client(.+))",
			userAgentHeader: "loki",
		},
		"should hit if regex matches - .*": {
			userAgentRegex:  ".*",
			userAgentHeader: "grafana-agent/v0.19.0",
			result:          true,
		},
		"should hit if regex is an empty string": {
			userAgentRegex:  "",
			userAgentHeader: "grafana-agent/v0.19.0",
			result:          true,
		},
	}

	for testName, testData := range tests {
		t.Run(testName, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", http.NoBody)
			require.NoError(t, err)
			req.Header = http.Header{
				"User-Agent": {testData.userAgentHeader},
			}
			queryAttribute := validation.QueryAttribute{
				UserAgentRegex:         testData.userAgentRegex,
				CompiledUserAgentRegex: regexp.MustCompile(testData.userAgentRegex),
			}

			result := matchAttributeForExpressionQuery(queryAttribute, "query_range", req, "")
			assert.Equal(t, testData.result, result)
		})
	}

}
