package wireguard

type Peer struct {
	publicKey       string
	allowIps        string
	endPoint        string
	latestHandshake string
}

func (p *Peer) GetPublicKey() string {
	return p.publicKey
}

func (p *Peer) GetAllowIps() string {
	return p.allowIps
}

func (p *Peer) GetEndPoint() string {
	return p.endPoint
}

func (p *Peer) GetLatestHandshake() string {
	return p.latestHandshake
}
