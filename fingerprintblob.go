package netcheck

import (
	"encoding/base64"
	"encoding/json"
)

// fingerprintBlob is a base64-encoded JSON slice of Fingerprints.
type fingerprintBlob string

// candidateBlob is a base64-encoded JSON slice of fingerprintCandidate.
type candidateBlob string

func (fb *fingerprintBlob) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(fb.Extract())
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return json.Marshal(encoded)
}

func (fb *fingerprintBlob) UnmarshalJSON(b []byte) error {
	var encoded string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return nil
	}
	if encoded == "" {
		*fb = wrap([]fingerprint{})
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	var fps []fingerprint
	if err := json.Unmarshal(decoded, &fps); err != nil {
		return err
	}
	*fb = wrap(fps)
	return nil
}

func (fb *fingerprintBlob) Extract() []fingerprint {
	var fps []fingerprint
	_ = json.Unmarshal([]byte(fb.decodeBase64()), &fps)
	return fps
}

func (fb *fingerprintBlob) decodeBase64() string {
	s, err := base64.StdEncoding.DecodeString(string(*fb))
	if err != nil {
		return "[]"
	}
	return string(s)
}

func wrap(fps []fingerprint) fingerprintBlob {
	data, _ := json.Marshal(fps)
	return fingerprintBlob(base64.StdEncoding.EncodeToString(data))
}

func (cb *candidateBlob) MarshalJSON() ([]byte, error) {
	data, err := json.Marshal(cb.Extract())
	if err != nil {
		return nil, err
	}
	encoded := base64.StdEncoding.EncodeToString(data)
	return json.Marshal(encoded)
}

func (cb *candidateBlob) UnmarshalJSON(b []byte) error {
	var encoded string
	if err := json.Unmarshal(b, &encoded); err != nil {
		return nil
	}
	if encoded == "" {
		*cb = wrapCandidates([]fingerprintCandidate{})
		return nil
	}
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}
	var fc []fingerprintCandidate
	if err := json.Unmarshal(decoded, &fc); err != nil {
		return err
	}
	*cb = wrapCandidates(fc)
	return nil
}

func (cb *candidateBlob) Extract() []fingerprintCandidate {
	var fc []fingerprintCandidate
	_ = json.Unmarshal([]byte(cb.decodeBase64()), &fc)
	return fc
}

func (cb *candidateBlob) decodeBase64() string {
	s, err := base64.StdEncoding.DecodeString(string(*cb))
	if err != nil {
		return "[]"
	}
	return string(s)
}

func wrapCandidates(fc []fingerprintCandidate) candidateBlob {
	data, _ := json.Marshal(fc)
	return candidateBlob(base64.StdEncoding.EncodeToString(data))
}
