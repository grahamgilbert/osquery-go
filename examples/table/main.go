package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewWritablePlugin("example_table", ExampleColumns(), ExampleGenerate, ExampleInsert, ExampleDelete))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func ExampleColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
		table.BigIntColumn("big_int"),
		table.DoubleColumn("double"),
	}
}

func ExampleGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, nil
}

func ExampleInsert(ctx context.Context, values *table.ValueArrayJSON) ([]map[string]string, error) {
	// fmt.Println(values)
	for _, value := range values.Values {
		fmt.Println(value)
	}
	return []map[string]string{
		{
			"id":     "1",
			"status": "success",
		},
	}, nil
}

func ExampleDelete(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	fmt.Println(queryContext)
	fmt.Println("DELETING")
	return []map[string]string{
		{
			"status": "success",
		},
	}, nil
}
