// cmd/fibratus/app/unisolate/unisolate.go

package unisolate

import (
    "github.com/spf13/cobra"
    "github.com/rabbitstack/fibratus/pkg/filter/action"
)

var Command = &cobra.Command{
    Use:   "unisolate",
    Short: "Remove machine isolation rules created by Fibratus",
    RunE:  unisolate,
}

func unisolate(cmd *cobra.Command, args []string) error {
    return action.Unisolate()
}
