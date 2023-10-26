package ssh3_test

import (
	"testing"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
)

func TestSrc(t *testing.T) {
	RegisterFailHandler(Fail)
	RunSpecs(t, "Src Suite")
}
