package wireguard

import "os/exec"

// add new net interface
func newNetInterface(name, address string) error {
	cmd := exec.Command("ip", "link", "add", "dev", name, "type", "wireguard")
	err := cmd.Run()
	if err != nil {
		return err
	}

	cmd = exec.Command("ip", "address", "add", "dev", name, address)

	return cmd.Run()
}
