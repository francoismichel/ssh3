package integration_tests

import (
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"time"

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
var privKeyPath string
var attackerPrivKeyPath string
var username string
// must exist on the machine to successfully run the tests
const serverBind = "127.0.0.1:4433"

func IPv6LoopbackAvailable(addrs []net.Addr) bool {
	for _, addr := range addrs {
		Expect(addr).To(BeAssignableToTypeOf(&net.IPNet{}))
		ip := addr.(*net.IPNet).IP
		if ip.To4() == nil && ip.To16() != nil && ip.IsLoopback() {
			// we found ::1, we can start the test
			return true
		}
	}
	return false
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cli/client/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = Build("../cli/server/main.go")
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

		privKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		Expect(fileExists(privKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	if serverSession != nil {
		serverSession.Terminate()
	}
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
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgs := func(privKeyPath string, additionalArgs... string) []string {
				args := []string{
					"-insecure",
					"-privkey", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, serverBind, DEFAULT_URL_PATH))
				return args
			}

			Context("Client behaviour", func() {
				It("Should connect using privkey", func() {
					clientArgs = append(getClientArgs(privKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})
	
				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(privKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(privKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(privKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(privKeyPath), "exit", "-1")
	
					command0 := exec.Command(ssh3Path, clientArgs0...)
					session, err := Start(command0, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
	
					command1 := exec.Command(ssh3Path, clientArgs1...)
					session, err = Start(command1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(1))
	
					command255 := exec.Command(ssh3Path, clientArgs255...)
					session, err = Start(command255, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
	
					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session, err = Start(commandMinus1, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(255))
				})

				// It checks that upon executing the client with the -forward-tcp,
				// a TCP socket is indeed well open on the client and is indeed forwarded
				// through the SSH3 connection towards the specified remote IP and port.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string) {
						serverStarted := make(chan struct{})
						// Start a TCP server on the specified remote IP and port
						go func() {
							defer close(serverStarted)
							defer GinkgoRecover()
							listener, err := net.ListenTCP("tcp", remoteAddr)
							Expect(err).ToNot(HaveOccurred())
							defer listener.Close()

							serverStarted <- struct{}{}

							conn, err := listener.Accept()
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()
				
							// Read message from client
							buffer := make([]byte, len(messageFromClient))
							_, err = conn.Read(buffer)
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))
				
							// Send message to client
							_, err = conn.Write([]byte(messageFromServer))
							Expect(err).ToNot(HaveOccurred())
							conn.(*net.TCPConn).CloseWrite()

							// Read from the client after receiving the message, assert EOF
							n, err := conn.Read(buffer)
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()
				
						Eventually(serverStarted).Should(Receive())
						// Execute the client with TCP port forwarding
						clientArgs := getClientArgs(privKeyPath, "-forward-tcp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						command := exec.Command(ssh3Path, clientArgs...)
						session, err := Start(command, GinkgoWriter, GinkgoWriter)
						Expect(err).ToNot(HaveOccurred())
						defer session.Terminate()
				
						// Try to connect to the local forwarded port
						localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
						var conn net.Conn
						// connection refused might happen betwen the time when the process starts and actually listens the socket
						Eventually(func() error {
							var err error
							conn, err = net.Dial("tcp", localAddr)
							return err
						}).ShouldNot(HaveOccurred())
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()
				
						// Send message from client
						n, err := conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromClient)))

						// Close the client-side connection
						conn.(*net.TCPConn).CloseWrite()
				
						// Read message from server
						buffer := make([]byte, len(messageFromServer))
						n, err = conn.Read(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(string(buffer[:n])).To(Equal(messageFromServer))
				
						// If the messages are correctly exchanged, the forwarding is working as expected
						// Now, check that the TCP conn is well closed and that no additional byte was sent
						n, err = conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8080, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
					})


					
					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						addrs, err := net.InterfaceAddrs()
						Expect(err).ToNot(HaveOccurred())
						if !IPv6LoopbackAvailable(addrs) {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8080, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
					})
				})
			})


			// It checks that upon executing the client with the -forward-udp,
			// a UDP socket is indeed well open on the client and is indeed forwarded
			// through the SSH3 connection towards the specified remote IP and port.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string) {
					serverStarted := make(chan struct{})
					// Start a UDP server on the specified remote IP and port
					go func() {
						defer close(serverStarted)
						defer GinkgoRecover()
						conn, err := net.ListenUDP("udp", remoteAddr)
						Expect(err).ToNot(HaveOccurred())
						defer conn.Close()

						serverStarted <- struct{}{}
			
						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := conn.ReadFromUDP(buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(clientAddr.IP.String()).To(Equal("127.0.0.1"))
						Expect(string(buffer[:n])).To(Equal(messageFromClient))
			
						// Send message to client
						_, err = conn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()
			
					Eventually(serverStarted).Should(Receive())
					// Execute the client with UDP port forwarding
					clientArgs := getClientArgs(privKeyPath, "-forward-udp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					defer session.Terminate()
			
					// Wait for some time to ensure that the client has established the forwarding
					time.Sleep(2 * time.Second)
			
					// Try to connect to the local forwarded port
					localAddr := fmt.Sprintf("127.0.0.1:%d", localPort)
					
					var conn net.Conn
					Eventually(func() error {
						var err error
						conn, err = net.Dial("udp", localAddr)
						return err
					}).ShouldNot(HaveOccurred())
					defer conn.Close()
			
					// Send message from client
					n, err := conn.Write([]byte(messageFromClient))
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromClient)))

					// Read message from server
					buffer := make([]byte, 2*len(messageFromServer))
					conn.SetReadDeadline(time.Now().Add(time.Millisecond))
					n, err = conn.Read(buffer)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))
				}
			
				It("works with small messages", func() {
					testUDPPortForwarding(8080, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})


				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8080,  &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
				})
			
				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					addrs, err := net.InterfaceAddrs()
					Expect(err).ToNot(HaveOccurred())
					if !IPv6LoopbackAvailable(addrs) {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8080, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
				})
			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session, err := Start(command, GinkgoWriter, GinkgoWriter)
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Eventually(string(session.Wait().Err.Contents())).Should(ContainSubstring("unauthorized"))
				})
			})
		})
	})
})
