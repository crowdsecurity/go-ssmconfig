package ssmconfig

import (
	"context"
	"fmt"
	"reflect"
	"strconv"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	// "github.com/aws/aws-sdk-go-v2/service/ssm/ssmiface"
)

type SSMClient interface {
	GetParameter(ctx context.Context, params *ssm.GetParameterInput, optFns ...func(*ssm.Options)) (*ssm.GetParameterOutput, error)
}

type SSMConfig struct {
	svc SSMClient
}

func (s *SSMConfig) getSSMParameter(parameterName string) (string, error) {
	output, err := s.svc.GetParameter(context.TODO(), &ssm.GetParameterInput{
		Name:           aws.String(parameterName),
		WithDecryption: aws.Bool(true),
	})

	if err != nil {
		return "", err
	}

	return *output.Parameter.Value, nil
}

func (s *SSMConfig) Process(i interface{}) error {
	v := reflect.ValueOf(i)

	if v.Kind() != reflect.Ptr {
		return fmt.Errorf("expected pointer to struct, got %T", i)
	}

	v = v.Elem()

	if v.Kind() != reflect.Struct {
		return fmt.Errorf("expected pointer to struct, got pointer to %T", i)
	}

	t := v.Type()

	for i := 0; i < v.NumField(); i++ {
		field := v.Field(i)
		if !field.CanSet() {
			continue
		}

		//fieldType := t.Field(i)
		tag := t.Field(i).Tag.Get("ssm")

		if tag == "" {
			continue
		}

		value, err := s.getSSMParameter(tag)

		if err != nil {
			return fmt.Errorf("error getting ssm parameter %s: %w", tag, err)
		}

		switch field.Kind() {
		case reflect.String:
			field.SetString(value)
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			intValue, err := strconv.ParseInt(value, 0, field.Type().Bits())
			if err != nil {
				return fmt.Errorf("error parsing int: %w", err)
			}
			field.SetInt(intValue)
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			uintValue, err := strconv.ParseUint(value, 0, field.Type().Bits())
			if err != nil {
				return fmt.Errorf("error parsing uint: %w", err)
			}
			field.SetUint(uintValue)
		case reflect.Bool:
			boolValue, err := strconv.ParseBool(value)
			if err != nil {
				return fmt.Errorf("error parsing bool: %w", err)
			}
			field.SetBool(boolValue)
		default:
			return fmt.Errorf("unsupported type %s", field.Kind())
		}

	}

	return nil
}

func NewSSMConfig(svc SSMClient) *SSMConfig {
	return &SSMConfig{svc: svc}
}
