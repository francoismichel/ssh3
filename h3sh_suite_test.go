package ssh3_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSsh3(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Ssh3 Suite")
}
