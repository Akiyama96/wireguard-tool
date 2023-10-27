package wireguard

import (
	"fmt"
	"github.com/spf13/cast"
	"net"
	"os/exec"
	"strings"
)

type NetInterface struct {
	name       string
	address    string
	privateKet string
	publicKey  string
	listenPort int
	peers      []*Peer
}

type Peer struct {
	publicKey       string
	allowIps        string
	endPoint        string
	latestHandshake string
}

// GetInfo Get wireguard Info
func GetInfo() ([]*NetInterface, error) {
	cmd := exec.Command("sudo", "wg")

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, err
	}

	outString := string(out)

	netInterfacesString := strings.Split(outString, "interface:")

	var netInterfaces = make([]*NetInterface, 0)
	for _, netInterfaceString := range netInterfacesString {
		netInterfaceString = strings.ReplaceAll(netInterfaceString, " ", "")
		if netInterfaceString == "" {
			continue
		}

		peersString := strings.Split(netInterfaceString, "peer:")
		if len(peersString) <= 0 {
			continue
		}

		netInterfaceInfoString := peersString[0]
		peersString = append(peersString[:0], peersString[1:]...)

		// parse net interface info from string
		netInterface, err := parseNetInterfaceInfo(netInterfaceInfoString)
		if err != nil {
			continue
		}

		var peers = make([]*Peer, 0)
		// parse net interfaces peers info from string
		for _, peerString := range peersString {
			peer, err := parsePeerInfo(peerString)
			if err != nil {
				continue
			}

			peers = append(peers, peer)
		}

		netInterface.peers = peers

		netInterfaces = append(netInterfaces, netInterface)
	}

	return netInterfaces, nil
}

// parse net interfaces info from info string
func parseNetInterfaceInfo(in string) (*NetInterface, error) {
	infos := strings.Split(in, "\n")
	if len(infos) <= 2 {
		return nil, fmt.Errorf("net interface info lines count error")
	}

	netInterface := &NetInterface{}
	netInterface.name = infos[0]
	infos = append(infos[:0], infos[1:]...)

	interfacesList, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, interfaces := range interfacesList {
		if interfaces.Name == netInterface.name {
			addresses, err := interfaces.Addrs()
			if err != nil {
				return nil, err
			}

			for _, addr := range addresses {
				netInterface.address = addr.String()
				break
			}

			break
		}
	}

	for _, info := range infos {
		rows := strings.Split(info, ":")
		if len(rows) < 2 {
			continue
		}

		var content string
		for i, row := range rows[1:] {
			if i > 0 {
				content += ":" + row
				continue
			}

			content = row
		}

		switch rows[0] {
		case "publickey":
			netInterface.publicKey = content
		case "privatekey":
			netInterface.privateKet = content
		case "listeningport":
			netInterface.listenPort = cast.ToInt(content)
		}
	}

	return netInterface, nil
}

// parse peer info from info string
func parsePeerInfo(in string) (*Peer, error) {
	infos := strings.Split(in, "\n")
	if len(infos) <= 2 {
		return nil, fmt.Errorf("peer info lines count error")
	}

	peer := &Peer{}
	peer.publicKey = infos[0]
	infos = append(infos[:0], infos[1:]...)

	for _, info := range infos {
		rows := strings.Split(info, ":")
		if len(rows) < 2 {
			continue
		}

		var content string
		for i, row := range rows[1:] {
			if i > 0 {
				content += ":" + row
				continue
			}

			content = row
		}

		switch rows[0] {
		case "endpoint":
			peer.endPoint = content
		case "allowedips":
			peer.allowIps = content
		case "latesthandshake":
			peer.latestHandshake = content
		}
	}

	return peer, nil
}
