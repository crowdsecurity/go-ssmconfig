package ssmconfig_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/ssm/types"
	"github.com/crowdsecurity/go-ssmconfig"
	"github.com/stretchr/testify/assert"
)

type mockSSMClient struct{}

func (m *mockSSMClient) GetParameter(ctx context.Context, input *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error) {
	switch *input.Name {
	case "/test/string":
		return &ssm.GetParameterOutput{
			Parameter: &types.Parameter{
				Value: aws.String("test"),
			},
		}, nil
	case "/test/valid-int":
		return &ssm.GetParameterOutput{
			Parameter: &types.Parameter{
				Value: aws.String("1"),
			},
		}, nil
	case "/test/invalid-int":
		return &ssm.GetParameterOutput{
			Parameter: &types.Parameter{
				Value: aws.String("notanint"),
			},
		}, nil
	case "/test/valid-bool":
		return &ssm.GetParameterOutput{
			Parameter: &types.Parameter{
				Value: aws.String("true"),
			},
		}, nil
	default:
		return nil, fmt.Errorf("invalid parameter name")
	}
}

func TestInvalidType(t *testing.T) {

	mockSvc := &mockSSMClient{}
	ssmgetter := ssmconfig.NewSSMConfig(mockSvc)

	tests := []struct {
		name    string
		input   interface{}
		wantErr bool
	}{
		{
			name:    "nil",
			input:   nil,
			wantErr: true,
		},
		{
			name:    "int",
			input:   1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ssmgetter.Process(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func TestValidStruct(t *testing.T) {

	type testStructString struct {
		SSMParameter string `ssm:"/test/string"`
	}

	type testStructInt struct {
		SSMParameter int `ssm:"/test/valid-int"`
	}

	type testStructInvalidInt struct {
		SSMParameter int `ssm:"/test/invalid-int"`
	}

	type testStructValidBool struct {
		SSMParameter bool `ssm:"/test/valid-bool"`
	}

	type testStructInvalidBool struct {
		SSMParameter bool `ssm:"/test/string"`
	}

	mockSvc := &mockSSMClient{}
	ssmgetter := ssmconfig.NewSSMConfig(mockSvc)

	tests := []struct {
		name     string
		input    interface{}
		expected interface{}
		wantErr  bool
	}{
		{
			name:  "/test/string",
			input: &testStructString{},
			expected: &testStructString{
				SSMParameter: "test",
			},
			wantErr: false,
		},
		{
			name:  "/test/valid-int",
			input: &testStructInt{},
			expected: &testStructInt{
				SSMParameter: 1,
			},
			wantErr: false,
		},
		{
			name:  "/test/invalid-int",
			input: &testStructInvalidInt{},
			expected: &testStructInvalidInt{
				SSMParameter: 0,
			},
			wantErr: true,
		},
		{
			name:  "/test/valid-bool",
			input: &testStructValidBool{},
			expected: &testStructValidBool{
				SSMParameter: true,
			},
			wantErr: false,
		},
		{
			name:  "/test/invalid-bool",
			input: &testStructInvalidBool{},
			expected: &testStructInvalidBool{
				SSMParameter: false,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ssmgetter.Process(tt.input)

			if (err != nil) != tt.wantErr {
				t.Errorf("Process() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			assert.Equal(t, tt.expected, tt.input)
		})
	}
}
