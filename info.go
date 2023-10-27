package wireguard

import (
	"fmt"
	"github.com/spf13/cast"
	"net"
	"os/exec"
	"strings"
)

type Permission string

const (
	PERMISSION_DEFAULT Permission = "default"
	PERMISSION_SUDO    Permission = "root"
)

// GetInfo Get wireguard Info
func GetInfo(permission ...Permission) ([]*NetInterface, error) {
	if len(permission) == 0 {
		permission = append(permission, PERMISSION_DEFAULT)
	}

	var cmd *exec.Cmd
	switch permission[0] {
	case PERMISSION_DEFAULT:
		cmd = exec.Command("wg")
	case PERMISSION_SUDO:
		cmd = exec.Command("sudo", "wg")
	default:
		return nil, fmt.Errorf("permission error")
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("get wireguard info error: %s, %s", err.Error(), string(out))
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

	interfaces, err := net.InterfaceByName(netInterface.name)
	if err != nil {
		return nil, err
	}

	addresses, err := interfaces.Addrs()
	if err != nil {
		return nil, err
	}

	for i, addr := range addresses {
		if i > 0 {
			netInterface.address += "," + addr.String()
		} else {
			netInterface.address = addr.String()
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
			netInterface.privateKey = content
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
