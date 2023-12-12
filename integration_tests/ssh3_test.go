package integration_tests

import (
	"fmt"
	"os"
	"os/exec"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var ssh3Path string
var ssh3ServerPath string
const DEFAULT_URL_PATH = "/ssh3-tests"
var serverCommand *exec.Cmd
var serverSession *Session
// must exist on the machine to successfully run the tests
const TESTUSER = "ssh3-testuser"
const TESTPASSWD = "ssh3-testpasswd"
const serverBind = "127.0.0.1:4433"

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../client/main.go")
	Expect(err).ToNot(HaveOccurred())
	ssh3ServerPath, err = Build("../server/main.go")
	Expect(err).ToNot(HaveOccurred())
	serverCommand = exec.Command(ssh3ServerPath,
									"-bind", serverBind,
									"-v",
									"-enable-password-login",
									"-url-path", DEFAULT_URL_PATH,
									"-cert", os.Getenv("CERT_PEM"),
									"-key", os.Getenv("CERT_PRIV_KEY"))
	serverCommand.Env = append(serverCommand.Env, "SSH3_LOG_LEVEL=debug")
	serverSession, err = Start(serverCommand, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	serverSession.Terminate()
})

var _ = Describe("Testing the ssh3 cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session, err := Start(command, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			Eventually(session).Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})
	})

	Context("With running server", func() {
		var privKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		var username = os.Getenv("TESTUSER_USERNAME")
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
		})

		Context("Insecure", func() {
			It("Should connect using privkey", func() {
				command := exec.Command(ssh3Path,
										"-insecure",
										"-privkey", privKeyPath,
										fmt.Sprintf("%s@%s%s", username, serverBind, DEFAULT_URL_PATH),
										"echo", "Hello, World!")
				session, err := Start(command, GinkgoWriter, GinkgoWriter)
				Expect(err).ToNot(HaveOccurred())
				Eventually(session).Should(Exit(0))
				Eventually(session).Should(Say("Hello, World!\n"))
			})
		})
	})
})
