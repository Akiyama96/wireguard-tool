package wireguard

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

type NetInterface struct {
	listenPort     int
	name           string
	address        string
	privateKey     string
	publicKey      string
	configFilePath string
	peers          []*Peer
}

const (
	DEFAULT_LINUX_CONFIG_FILE_PATH  = "/etc/wireguard"
	DEFAULT_DARWIN_CONFIG_FILE_PATH = "~/wireguard"
)

// NewNetInterface Create new net interface
func NewNetInterface(name, address string, listenPort int) (*NetInterface, error) {

	var filePath, fileName string
	switch runtime.GOOS {
	case "linux":
		filePath = DEFAULT_LINUX_CONFIG_FILE_PATH
		fileName = name + ".conf"
		err := newNetInterface(name, address)
		if err != nil {
			return nil, err
		}
	case "darwin":
		filePath = DEFAULT_DARWIN_CONFIG_FILE_PATH
		fileName = name + ".conf"
	default:
		return nil, fmt.Errorf("not support os: %s", runtime.GOOS)
	}

	err := os.MkdirAll(filePath, 0755)
	if err != nil {
		return nil, err
	}

	n := &NetInterface{
		name:           name,
		listenPort:     listenPort,
		configFilePath: filePath + "" + fileName,
	}

	err = n.createKey()
	if err != nil {
		return nil, err
	}

	privateKeyBytes, err := os.ReadFile(filePath + "/" + "private.key")
	if err != nil {
		return nil, err
	}

	publicKeyBytes, err := os.ReadFile(filePath + "/" + "public.key")
	if err != nil {
		return nil, err
	}

	n.privateKey = string(privateKeyBytes)
	n.publicKey = string(publicKeyBytes)

	return n, nil
}

// AddPeer Add peer to net interface
func (n *NetInterface) AddPeer(publicKey, allowIps string, endPoint ...string) {
	peer := &Peer{
		publicKey: publicKey,
		allowIps:  allowIps,
	}

	if len(endPoint) > 0 {
		peer.endPoint = endPoint[0]
	}

	n.peers = append(n.peers, peer)
}

// DeletePeer Delete peer from net interface
func (n *NetInterface) DeletePeer(publicKey string) {
	for i, peer := range n.peers {
		if peer.publicKey == publicKey {
			n.peers = append(n.peers[:i], n.peers[i+1:]...)
			break
		}
	}
}

// Apply use the config file apply to system net interface
func (n *NetInterface) Apply() error {
	file, err := os.OpenFile(n.configFilePath, os.O_WRONLY|os.O_CREATE|os.O_SYNC|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("failed to open file: %v", err)
	}

	defer func() {
		_ = file.Close()
	}()

	var configFileContent string
	switch runtime.GOOS {
	case "linux":
		configFileContent = fmt.Sprintf(
			"[Interface]\nPrivateKey = %s\nListenPort = %d\n\n",
			n.privateKey, n.listenPort,
		)
	case "darwin":
		configFileContent = fmt.Sprintf(
			"[Interface]\nAddress = %s\nPrivateKey = %s\nListenPort = %d\n\n",
			n.address, n.privateKey, n.listenPort,
		)
	default:
		return fmt.Errorf("not support os: %s", runtime.GOOS)
	}

	for _, peer := range n.peers {
		configFileContent += fmt.Sprintf(
			"[Peer]\nPublicKey = %s\nAllowedIPs = %s\n",
			peer.publicKey, peer.allowIps,
		)

		if peer.endPoint != "" {
			configFileContent += fmt.Sprintf("Endpoint = %s\n", peer.endPoint)
		} else {
			configFileContent += "\n"
		}
	}

	_, err = file.WriteString(configFileContent)
	if err != nil {
		return err
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("wg", "setconf", n.name, n.configFilePath)
		err = cmd.Run()
		if err != nil {
			return err
		}

		cmd = exec.Command("ip", "link", "set", n.name, "up")
	case "darwin":
		cmd = exec.Command("wg-quick", "up", n.configFilePath)
	default:
		return fmt.Errorf("not support os: %s", runtime.GOOS)
	}

	return cmd.Run()
}

// Down set net interface down
func (n *NetInterface) Down() error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "link", "set", n.name, "down")
	case "darwin":
		cmd = exec.Command("wg-quick", "down", n.configFilePath)
	}

	return cmd.Run()
}

func (n *NetInterface) GetName() string {
	return n.name
}

func (n *NetInterface) GetAddress() string {
	return n.address
}

func (n *NetInterface) GetPublicKey() string {
	return n.publicKey
}

func (n *NetInterface) GetListenPort() int {
	return n.listenPort
}

func (n *NetInterface) GetPeers() []*Peer {
	return n.peers
}

// createKey create private key and public key
func (n *NetInterface) createKey() error {
	cmd := exec.Command("umask", "077")
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("wg", "genkey", ">", "private.key")
	err = cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("wg", "pubkey", "<", "private.key", ">", "public.key")
	return cmd.Run()
}
