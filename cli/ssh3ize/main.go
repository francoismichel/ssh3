package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"

	"github.com/google/go-github/v57/github"
)

func getUsage(execName string) func() {
	return func() {
		fmt.Fprintf(os.Stderr, "%s installs ssh3-server on your remote host if it already supports SSHv2.\n", execName)
		fmt.Fprintf(os.Stderr, "It requires you to have OpenSSH running on your remote host and on your client running this program.\n")
		fmt.Fprintf(os.Stderr, "It currently only works with x86_64 linux servers (any distribution will work).\n")
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "Usage: %s [OPTIONS] SSH_COMMAND ...\n", os.Args[0])
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "  SSH_COMMAND is the command you would use to log in to your remote host in an interactive shell.\n")
		fmt.Fprintf(os.Stderr, "  For example, the following command will install ssh3-server on your remote host located at 192.0.2.0, listening on path \"/secret-path\":\n")
		fmt.Fprintf(os.Stderr, "  %s -url-path ssh root@192.0.2.0\n", execName)
		fmt.Fprintf(os.Stderr, "  You can use the -dry-run flag to just print the command that should be run to install ssh3-server on your remote host.\n")
	}
}

func findMatchingAsset(release *github.RepositoryRelease) (string, error) {
	regexPattern := `ssh3_\d+.\d+.\d+_linux_x86_64.tar.gz`
	regex, err := regexp.Compile(regexPattern)
	if err != nil {
		return "", err
	}
	for _, asset := range release.Assets {
		splittedUrl := strings.Split(*asset.BrowserDownloadURL, "/")
		lastURLPart := splittedUrl[len(splittedUrl)-1]
		var ok bool
		if ok = regex.Match([]byte(lastURLPart)); ok {
			fmt.Fprintln(os.Stderr, "found matching release:", lastURLPart)
			return *asset.BrowserDownloadURL, nil
		}
	}
	return "", fmt.Errorf("no asset matching %s", regexPattern)
}

func main() {
	flag.Usage = getUsage(os.Args[0])
	bindAddr := flag.String("bind", "[::]:443", "the address:port pair to listen to, e.g. 0.0.0.0:443")
	verbose := flag.Bool("v", false, "verbose mode, if set")
	enablePasswordLogin := flag.Bool("enable-password-login", false, "if set, enable password authentication (disabled by default)")
	urlPath := flag.String("url-path", "/ssh3-term", "the secret URL path on which the ssh3 server listens")
	remoteReleaseFilePath := flag.String("remote-release-file-path", "/tmp/ssh3-latest-release.tar.gz", "the path to store the release archive on the server")
	remoteBinaryDirPath := flag.String("remote-binary-dir-path", "/usr/bin", "the path to store the ssh3-server binary")
	dryRun := flag.Bool("dry-run", false, "if set, only print the command to execute on the remote host instead of executing from here")
	sshCommand := flag.Args()


	flag.Parse()

	client := github.NewClient(nil)
	release, _, err := client.Repositories.GetLatestRelease(context.Background(), "francoismichel", "ssh3")
	if err != nil {
		log.Fatalf("could not get latest SSH3 release: %s", err)
	}
	asset, err := findMatchingAsset(release)
	if err != nil {
		log.Fatalf("could not find suitable release asset: %s", err)
	}
	wgetCmd := fmt.Sprintf("wget -O %s %s", *remoteReleaseFilePath, asset)
	tarCmd := fmt.Sprintf("tar -C %s -x ssh3-server -z -v -f %s", *remoteBinaryDirPath, *remoteReleaseFilePath)
	verboseFlag := ""
	if *verbose {
		verboseFlag = "-verbose"
	}
	passwordFlag := ""
	if *enablePasswordLogin {
		passwordFlag = "-enable-password-login"
	}

	ssh3ServerCommand := fmt.Sprintf("screen -d -m %s/ssh3-server -bind %s -url-path %s %s %s", *remoteBinaryDirPath, *bindAddr, *urlPath, verboseFlag, passwordFlag)
	shellCommandToRun := strings.Join([]string{wgetCmd, tarCmd, ssh3ServerCommand}, " && ")
	if *dryRun {
		fmt.Println(shellCommandToRun)
		os.Exit(0)
	}
	sshCommandToRun := sshCommand
	sshCommandToRun = append(sshCommandToRun, "sh", "-c", shellCommandToRun)
	cmd := exec.Command(sshCommandToRun[0], sshCommandToRun[1:]...)
	err = cmd.Run()
	if err != nil {
		log.Fatalf("error running the remote command: %s", err)
	}
	fmt.Fprintln(os.Stderr, "success !")
}