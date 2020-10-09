package table

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/pkg/errors"
)

type InsertFunc func(ctx context.Context, values *ValueArrayJSON) ([]map[string]string, error)

// Will this need the context like selecting?
type DeleteFunc func(ctx context.Context, queryContext QueryContext) ([]map[string]string, error)

type WritablePlugin struct {
	name     string
	columns  []ColumnDefinition
	generate GenerateFunc
	insert   InsertFunc
	delete   DeleteFunc
}

func NewWritablePlugin(name string, columns []ColumnDefinition, gen GenerateFunc, insert InsertFunc, delete DeleteFunc) *WritablePlugin {
	return &WritablePlugin{
		name:     name,
		columns:  columns,
		generate: gen,
		insert:   insert,
		delete:   delete,
	}
}

func (t *WritablePlugin) Name() string {
	return t.name
}

func (t *WritablePlugin) RegistryName() string {
	return "table"
}

func (t *WritablePlugin) Routes() osquery.ExtensionPluginResponse {
	routes := []map[string]string{}
	for _, col := range t.columns {
		routes = append(routes, map[string]string{
			"id":   "column",
			"name": col.Name,
			"type": string(col.Type),
			"op":   "0",
		})
	}
	return routes
}

func (t *WritablePlugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	fmt.Println(request)
	switch request["action"] {
	case "generate":
		queryContext, err := parseQueryContext(request["context"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing context JSON: " + err.Error(),
				},
			}
		}

		rows, err := t.generate(ctx, *queryContext)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error generating table: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: rows,
		}
	case "insert":
		values, err := parseJsonValueArray(request["json_value_array"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing value array json: " + err.Error(),
				},
			}
		}

		rows, err := t.insert(ctx, values)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error generating table: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: rows,
		}

	case "delete":
		fmt.Println("DLETEEEE")
		queryContext, err := parseQueryContext(request["context"])
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error parsing context JSON: " + err.Error(),
				},
			}
		}

		rows, err := t.delete(ctx, *queryContext)
		if err != nil {
			return osquery.ExtensionResponse{
				Status: &osquery.ExtensionStatus{
					Code:    1,
					Message: "error generating table: " + err.Error(),
				},
			}
		}

		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: rows,
		}
	case "columns":
		return osquery.ExtensionResponse{
			Status:   &ok,
			Response: t.Routes(),
		}

	default:
		return osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "unknown action: " + request["action"],
			},
		}
	}

}

func (t *WritablePlugin) Ping() osquery.ExtensionStatus {
	return osquery.ExtensionStatus{Code: 0, Message: "OK"}
}

func (t *WritablePlugin) Shutdown() {}

// The following types and functions exist for parsing of the value array
// JSON and are not made public.
type ValueArrayJSON struct {
	Values []interface{}
}

func parseJsonValueArray(valueJSON string) (*ValueArrayJSON, error) {
	var parsed ValueArrayJSON

	err := json.Unmarshal([]byte(valueJSON), &parsed.Values)
	if err != nil {
		return nil, errors.Wrap(err, "unmarshaling values JSON")
	}
	return &parsed, nil
}
