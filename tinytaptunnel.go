/*
 * tinytaptunnel v1.0 - Vanya A. Sergeev - vsergeev at gmail
 *
 * Point-to-Point Layer 2 tap interface tunnel over UDP/IP, with optional
 * encryption. See README.md for more information.
 */

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"hash/crc32"
	"io/ioutil"
	"net"
	"os"
	"syscall"
	"unsafe"
)

const (
	/* Key and IV size for 256-bit AES */
	KEY_SIZE = 32
	IV_SIZE  = 16
	/* SHA1 Hash Size */
	HASH_SIZE = 20
	/* CRC-32 Size */
	CHK_SIZE = 4
	/* RSA OAEP Encrypted Size */
	OAEP_SIZE = 256

	/* UDP Payload MTU */
	UDP_MTU = 1472
	/* Tap Encrypted Payload MTU */
	TAP_ENCRYPTED_MTU = UDP_MTU - OAEP_SIZE - CHK_SIZE - 14
	/* Tap Plaintext Payload MTU */
	TAP_PLAINTEXT_MTU = UDP_MTU - CHK_SIZE - 14

	/* Debug levels 0 (off), 1 (report discarded frames), 2 (verbose) */
	DEBUG = 1
)

/**********************************************************************/
/*** RSA PEM Key File ***/
/**********************************************************************/

func read_pem(filename string) ([]byte, error) {
	/* Read the ASCII-encoded PEM file */
	rawpem, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error reading file!: %s", err.Error()))
	}

	/* Decode into a PEM block */
	blockpem, _ := pem.Decode(rawpem)
	if len(blockpem.Bytes) == 0 {
		return nil, errors.New("Error decoding PEM key!")
	}

	return blockpem.Bytes, nil
}

func read_rsa_pubkey(filename string) (rsa_pubkey *rsa.PublicKey, err error) {
	/* Read the PEM file */
	pembytes, err := read_pem(filename)
	if err != nil {
		return nil, err
	}

	/* Parse the Public Key */
	generic_pubkey, err := x509.ParsePKIXPublicKey(pembytes)
	if err != nil {
		return nil, errors.New("Error parsing DER encoded public key!")
	}

	/* Make sure it's an RSA public key */
	switch pubkey := generic_pubkey.(type) {
	case *rsa.PublicKey:
		rsa_pubkey = pubkey
	default:
		return nil, errors.New("Error, invalid public key type!")
	}

	return rsa_pubkey, nil
}

func read_rsa_prikey(filename string) (rsa_prikey *rsa.PrivateKey, err error) {
	/* Read the PEM file */
	pembytes, err := read_pem(filename)
	if err != nil {
		return nil, err
	}

	/* Parse the Private Key */
	rsa_prikey, err = x509.ParsePKCS1PrivateKey(pembytes)
	if err != nil {
		return nil, errors.New("Error parsing DER encoded private key!")
	}

	return rsa_prikey, nil
}

/**********************************************************************/
/*** Plaintext Frame Encapsulation ***/
/**********************************************************************/

/* Plaintext Frame Format is:
 * | CRC-32 (4 bytes) | Original Frame (original frame len) |
 */

func encap_frame(frame []byte) (enc_frame []byte) {
	/* Compute the CRC32 of the frame */
	crc_uint32 := crc32.ChecksumIEEE(frame)
	crc_bytes := []byte{byte(crc_uint32), byte(crc_uint32 >> 8), byte(crc_uint32 >> 16), byte(crc_uint32 >> 24)}

	/* Prepend CRC to original frame */
	return append(crc_bytes, frame...)
}

func decap_frame(total_enc_frame []byte) (frame []byte, inv error) {
	/* Check that the encapsulated frame size is valid */
	if len(total_enc_frame) < CHK_SIZE {
		return nil, errors.New("Invalid encapsulated frame size!")
	}

	/* Verify the checksum */
	crc_uint32 := crc32.ChecksumIEEE(total_enc_frame[CHK_SIZE:])
	crc_bytes := []byte{byte(crc_uint32), byte(crc_uint32 >> 8), byte(crc_uint32 >> 16), byte(crc_uint32 >> 24)}
	if bytes.Compare(crc_bytes, total_enc_frame[0:CHK_SIZE]) != 0 {
		return nil, errors.New("Invalid checksum")
	}

	return total_enc_frame[CHK_SIZE:], nil
}

/**********************************************************************/
/*** Encrypted Frame Encapsulation ***/
/**********************************************************************/

/* Total Encrypted Frame Format is:
 * | CRC-32 (4 bytes) | RSA OAEP Encrypted Key, IV, Payload Hash (256 bytes) |
 * | AES-256 CTR Encrypted Payload (original frame len)                      |
 *
 * Plaintext Key, IV, and Hash are:
 * | Key (32 bytes) | IV (16 bytes) | Payload SHA1 Hash (20 bytes) |
 *
 * 1. 256-bit key and 128-bit IV are pseudo-randomly generated
 * 2. Payload SHA1 Hash is computed
 * 3. Key, IV, Payload SHA1 Hash are encrypted / encapsulated with RSA-OAEP
 * 4. Plaintext is encrypted with AES in CTR mode using key and IV
 * 5. CRC-32 of the Encrypted Key/IV/Hash and Encrypted Frame is calculated
 * 6. Total encrypted frame is assembled as laid out above
 */

func encrypt_frame(frame []byte, rsa_pubkey *rsa.PublicKey) (total_enc_frame []byte, err error) {
	/* Byte slice for the 256-bit key, 128-bit IV */
	key_iv_hash := make([]byte, KEY_SIZE+IV_SIZE+HASH_SIZE)

	/* Generate random bytes for the key and IV */
	_, err = rand.Read(key_iv_hash)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error generating random bytes for key and IV!: %s", err.Error()))
	}

	/* Compute SHA1 hash of payload */
	h := sha1.New()
	key_iv_hash = append(key_iv_hash, h.Sum(frame)...)

	/* Encrypt the key, IV, and hash with RSA OAEP */
	enc_key_iv_hash, err := rsa.EncryptOAEP(h, rand.Reader, rsa_pubkey, key_iv_hash, nil)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error encrypting key + IV + hash with RSA OAEP!: %s", err.Error()))
	}

	/* Create an AES cipher interface */
	aes_cipher, err := aes.NewCipher(key_iv_hash[0:KEY_SIZE])
	if err != nil {
		return nil, errors.New(fmt.Sprintf("Error creating AES cipher instance!: %s", err.Error()))
	}

	/* Encrypt the frame with AES in CTR mode */
	ctr := cipher.NewCTR(aes_cipher, key_iv_hash[KEY_SIZE:KEY_SIZE+IV_SIZE])
	enc_frame := make([]byte, len(frame))
	ctr.XORKeyStream(enc_frame, frame)

	/* Combine the encrypted key / IV and the encrypted frame into one slice */
	total_enc_frame = append(enc_key_iv_hash, enc_frame...)

	/* Compute the CRC32 of the frame */
	crc_uint32 := crc32.ChecksumIEEE(total_enc_frame)
	crc_bytes := []byte{byte(crc_uint32), byte(crc_uint32 >> 8), byte(crc_uint32 >> 16), byte(crc_uint32 >> 24)}

	total_enc_frame = append(crc_bytes, total_enc_frame...)

	return total_enc_frame, nil
}

func decrypt_frame(total_enc_frame []byte, rsa_prikey *rsa.PrivateKey) (frame []byte, inv error, err error) {
	/* Check that the encrypted frame size is valid */
	if len(total_enc_frame) < CHK_SIZE+OAEP_SIZE {
		return nil, errors.New("Invalid encrypted frame size"), nil
	}

	/* Verify the checksum */
	crc_uint32 := crc32.ChecksumIEEE(total_enc_frame[CHK_SIZE:])
	crc_bytes := []byte{byte(crc_uint32), byte(crc_uint32 >> 8), byte(crc_uint32 >> 16), byte(crc_uint32 >> 24)}
	if bytes.Compare(crc_bytes, total_enc_frame[0:CHK_SIZE]) != 0 {
		return nil, errors.New("Invalid checksum"), nil
	}

	/* Decrypt the key, IV, and hash with RSA OAEP */
	h := sha1.New()
	key_iv_hash, err := rsa.DecryptOAEP(h, rand.Reader, rsa_prikey, total_enc_frame[CHK_SIZE:CHK_SIZE+OAEP_SIZE], nil)
	if err != nil {
		return nil, errors.New("Decrypting OAEP RSA payload failed"), nil
	}

	/* Ensure that we decrypted a valid key, IV, and hash */
	if len(key_iv_hash) != KEY_SIZE+IV_SIZE+HASH_SIZE {
		return nil, errors.New("Invalid OAEP RSA decrypted payload"), nil
	}

	/* Create an AES cipher interface */
	aes_cipher, err := aes.NewCipher(key_iv_hash[0:KEY_SIZE])
	if err != nil {
		return nil, nil, errors.New(fmt.Sprintf("Error creating AES cipher instance!: %s", err.Error()))
	}

	/* Decrypt the frame with AES in CTR mode */
	ctr := cipher.NewCTR(aes_cipher, key_iv_hash[KEY_SIZE:KEY_SIZE+IV_SIZE])
	frame = make([]byte, len(total_enc_frame)-OAEP_SIZE-CHK_SIZE)
	ctr.XORKeyStream(frame, total_enc_frame[CHK_SIZE+OAEP_SIZE:])

	/* Verify the SHA1 hash for the frame */
	if bytes.Compare(h.Sum(frame), key_iv_hash[KEY_SIZE+IV_SIZE:KEY_SIZE+IV_SIZE+HASH_SIZE]) != 0 {
		return nil, errors.New("Invalid payload hash"), nil
	}

	return frame, nil, nil
}

/**********************************************************************/
/*** Tap Device Open/Close/Read/Write ***/
/**********************************************************************/

type TapConn struct {
	fd     int
	ifname string
}

func (tap_conn *TapConn) Open(mtu uint) (err error) {
	/* Open the tap-tun device */
	tap_conn.fd, err = syscall.Open("/dev/net/tun", syscall.O_RDWR, syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IRGRP|syscall.S_IROTH)
	if err != nil {
		return errors.New(fmt.Sprintf("Error opening device /dev/net/tun!: %s", err.Error()))
	}

	/* Prepare a struct ifreq structure for TUNSETIFF with tap settings */
	ifr_flags := uint32(syscall.IFF_TAP | syscall.IFF_NO_PI)
	/* FIXME: Assumes little endian */
	ifr_struct := make([]byte, 32)
	ifr_struct[16] = byte(ifr_flags)
	ifr_struct[17] = byte(ifr_flags >> 8)
	ifr_struct[18] = byte(ifr_flags >> 16)
	ifr_struct[19] = byte(ifr_flags >> 24)
	r0, _, err := syscall.Syscall(syscall.SYS_IOCTL, uintptr(tap_conn.fd), syscall.TUNSETIFF, uintptr(unsafe.Pointer(&ifr_struct[0])))
	if r0 != 0 {
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error setting tun type!: %s", err.Error()))
	}

	/* Extract the assigned interface name into a string */
	tap_conn.ifname = string(ifr_struct[0:16])

	/* Create a raw socket for our tap interface, so we can set the MTU */
	tap_sockfd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error creating packet socket!: %s", err.Error()))
	}

	/* Bind the raw socket to our tap interface */
	err = syscall.BindToDevice(tap_sockfd, tap_conn.ifname)
	if err != nil {
		syscall.Close(tap_sockfd)
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error binding packet socket to tap interface!: %s", err.Error()))
	}

	/* Prepare a ifreq structure for SIOCSIFMTU with MTU setting */
	ifr_mtu := mtu
	/* FIXME: Assumes little endian */
	ifr_struct[16] = byte(ifr_mtu)
	ifr_struct[17] = byte(ifr_mtu >> 8)
	ifr_struct[18] = byte(ifr_mtu >> 16)
	ifr_struct[19] = byte(ifr_mtu >> 24)
	r0, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(tap_sockfd), syscall.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifr_struct[0])))
	if r0 != 0 {
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error setting MTU!: %s", err.Error()))
	}

	/* Get the current interface flags in ifr_struct */
	r0, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(tap_sockfd), syscall.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifr_struct[0])))
	if r0 != 0 {
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error getting tun interface flags!: %s", err.Error()))
	}
	/* Update the interface flags to bring the interface up */
	ifr_flags = uint32(ifr_struct[16]) | uint32(ifr_struct[17]<<8) | uint32(ifr_struct[18]<<16) | uint32(ifr_struct[19]<<24)
	ifr_flags |= syscall.IFF_UP | syscall.IFF_RUNNING
	/* FIXME: Assumes little endian */
	ifr_struct[16] = byte(ifr_flags)
	ifr_struct[17] = byte(ifr_flags >> 8)
	ifr_struct[18] = byte(ifr_flags >> 16)
	ifr_struct[19] = byte(ifr_flags >> 24)
	r0, _, err = syscall.Syscall(syscall.SYS_IOCTL, uintptr(tap_sockfd), syscall.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifr_struct[0])))
	if r0 != 0 {
		tap_conn.Close()
		return errors.New(fmt.Sprintf("Error bringing up tun interface!: %s", err.Error()))
	}

	/* We don't need the socket file descriptor any more, now that we've
	 * brought the interface up and set the MTU */
	syscall.Close(tap_sockfd)

	return nil
}

func (tap_conn *TapConn) Close() {
	syscall.Close(tap_conn.fd)
}

func (tap_conn *TapConn) Read(b []byte) (n int, err error) {
	return syscall.Read(tap_conn.fd, b)
}

func (tap_conn *TapConn) Write(b []byte) (n int, err error) {
	return syscall.Write(tap_conn.fd, b)
}

/**********************************************************************/
/** Tap / Physical Forwarding ***/
/**********************************************************************/

func forward_phys_to_tap(phys_conn *net.UDPConn, tap_conn *TapConn, peer_addr *net.UDPAddr, local_prikey *rsa.PrivateKey) {
	packet := make([]byte, UDP_MTU)
	var dec_frame []byte
	var inv error = nil

	for {
		/* Read an encrypted/encapsulated frame packet from UDP */
		n, raddr, err := phys_conn.ReadFromUDP(packet)
		check_error_fatal(err, "Error reading from UDP socket!: %s\n")

		/* Ensure it's addressed from our peer */
		if !raddr.IP.Equal(peer_addr.IP) {
			continue
		}

		if DEBUG == 2 {
			fmt.Println("<- phys | Encrypted frame:")
			fmt.Println(hex.Dump(packet[0:n]))
		}

		/* Encrypted mode */
		if local_prikey != nil {
			/* Decrypt the frame */
			dec_frame, inv, err = decrypt_frame(packet[0:n], local_prikey)
			check_error_fatal(err, "Error decrypting frame!: %s\n")

		/* Plaintext mode */
		} else {
			/* Decapsulate the frame */
			dec_frame, inv = decap_frame(packet[0:n])
		}

		/* Skip it if it's invalid */
		if inv != nil {
			if DEBUG >= 1 {
				fmt.Printf("<- phys | Frame discarded! Size: %d, Reason: %s\n", n, inv.Error())
				fmt.Println(hex.Dump(packet[0:n]))
			}
			continue
		}

		if DEBUG == 2 {
			fmt.Println("-> tap  | Decrypted frame:")
			fmt.Println(hex.Dump(dec_frame))
		}

		/* Forward the decrypted/decapsulate frame to our tap interface */
		_, err = tap_conn.Write(dec_frame)
		check_error_fatal(err, "Error writing to tap device!: %s\n")
	}
}

func forward_tap_to_phys(phys_conn *net.UDPConn, tap_conn *TapConn, peer_addr *net.UDPAddr, peer_pubkey *rsa.PublicKey) {
	frame := make([]byte, UDP_MTU)
	var enc_frame []byte

	for {
		/* Read a raw frame from our tap device */
		n, err := tap_conn.Read(frame)
		check_error_fatal(err, "Error reading from tap device!: %s\n")

		if DEBUG == 2 {
			fmt.Println("<- tap  | Plaintext frame:")
			fmt.Println(hex.Dump(frame[0:n]))
		}

		/* Encrypted mode */
		if peer_pubkey != nil {
			/* Encrypt the frame */
			enc_frame, err = encrypt_frame(frame[0:n], peer_pubkey)
			check_error_fatal(err, "Error encrypting frame!: %s\n")

		/* Plaintext mode */
		} else {
			/* Encapsulate the frame */
			enc_frame = encap_frame(frame[0:n])
		}

		if DEBUG == 2 {
			fmt.Println("-> phys | Encrypted frame:")
			fmt.Println(hex.Dump(enc_frame))
		}

		/* Forward the encrypted/encapsulate frame to our physical
 		 * interface */
		_, err = phys_conn.WriteToUDP(enc_frame, peer_addr)
		check_error_fatal(err, "Error writing to UDP socket!: %s\n")
	}
}

func check_error_fatal(err error, format string) {
	if err != nil {
		fmt.Printf(format, err.Error())
		os.Exit(1)
	}
}

func main() {
	var local_prikey *rsa.PrivateKey = nil
	var peer_pubkey *rsa.PublicKey = nil
	var tap_mtu uint
	var encrypted bool = false

	if len(os.Args) != 3 && len(os.Args) != 5 {
		fmt.Println("tinytaptunnel v1.0 Usage\n")
		fmt.Println("Plaintext Mode")
		fmt.Printf("  %s <local address> <peer address>\n", os.Args[0])
		fmt.Println("\nEncrypted Mode")
		fmt.Printf("  %s <local address> <peer address> <local prikey> <peer pubkey>\n", os.Args[0])
		os.Exit(1)
	}

	if len(os.Args) == 5 {
		/* Encrypted mode */
		var err error

		/* Load key files for encrypted mode */
		local_prikey, err = read_rsa_prikey(os.Args[3])
		check_error_fatal(err, "Error reading private RSA private key!: %s")
		peer_pubkey, err = read_rsa_pubkey(os.Args[4])
		check_error_fatal(err, "Error reading peer RSA public key!: %s")

		encrypted = true
		tap_mtu = TAP_ENCRYPTED_MTU
	} else {
		/* Plaintext mode */
		tap_mtu = TAP_PLAINTEXT_MTU
	}

	/* Parse & resolve local address */
	local_addr, err := net.ResolveUDPAddr("udp", os.Args[1])
	check_error_fatal(err, "Error resolving local address!: %s\n")

	/* Parse & resolve peer address */
	peer_addr, err := net.ResolveUDPAddr("udp", os.Args[2])
	check_error_fatal(err, "Error resolving peer address!: %s\n")

	/* Create UDP socket */
	phys_conn, err := net.ListenUDP("udp", local_addr)
	check_error_fatal(err, "Error creating a UDP socket!: %s\n")

	/* Create tap interface */
	tap_conn := new(TapConn)
	err = tap_conn.Open(tap_mtu)
	check_error_fatal(err, "Error opening a tap device!: %s\n")

	fmt.Printf("Created tunnel at interface %s with MTU %d\n\n", tap_conn.ifname, tap_mtu)
	if encrypted {
		fmt.Println("Starting encrypted tinytaptunnel...")
	} else {
		fmt.Println("Starting plaintext tinytaptunnel...")
	}

	/* Run two goroutines for forwarding between interfaces */
	go forward_phys_to_tap(phys_conn, tap_conn, peer_addr, local_prikey)
	forward_tap_to_phys(phys_conn, tap_conn, peer_addr, peer_pubkey)
}

