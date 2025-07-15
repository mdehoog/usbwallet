package usbwallet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"reflect"

	"github.com/base/usbwallet/trezor"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/signer/core/apitypes"
	"google.golang.org/protobuf/proto"
)

func (w *trezorDriver) SignText(path accounts.DerivationPath, text []byte) ([]byte, error) {
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}
	response := new(trezor.EthereumMessageSignature)
	_, err := w.trezorExchange(&trezor.EthereumSignMessage{
		AddressN: path,
		Message:  text,
	}, response)
	if err != nil {
		return nil, err
	}
	return response.Signature, nil
}

func (w *trezorDriver) SignedTypedData(path accounts.DerivationPath, data apitypes.TypedData) ([]byte, error) {
	if w.device == nil {
		return nil, accounts.ErrWalletClosed
	}

	_, hashes, err := apitypes.TypedDataAndHash(data)
	if err != nil {
		return nil, fmt.Errorf("trezor: error hashing typed data: %w", err)
	}
	domainHash, messageHash := hashes[2:34], hashes[34:66]
	if w.version[0] == 1 {
		// legacy Trezor devices don't support typed data; fallback to hash signing:
		return w.SignTypedHash(path, []byte(domainHash), []byte(messageHash))
	}

	signature := new(trezor.EthereumTypedDataSignature)
	structRequest := new(trezor.EthereumTypedDataStructRequest)
	valueRequest := new(trezor.EthereumTypedDataValueRequest)
	var req proto.Message = &trezor.EthereumSignTypedData{
		AddressN:        path,
		PrimaryType:     &data.PrimaryType,
		ShowMessageHash: []byte(messageHash),
	}
	nestedArray := false
	for {
		n, err := w.trezorExchange(req, signature, structRequest, valueRequest)
		if err != nil {
			var trezorFailure *TrezorFailure
			if nestedArray && errors.As(err, &trezorFailure) &&
				trezorFailure.Code != nil && *trezorFailure.Code == trezor.Failure_Failure_FirmwareError {
				return nil, fmt.Errorf("trezor: nested arrays are not supported by this firmware version: %w", err)
			}
			return nil, err
		}
		nestedArray = false
		switch n {
		case 0:
			// No additional data needed, return the signature
			return signature.Signature, nil
		case 1:
			fields := data.Types[structRequest.GetName()]
			if len(fields) == 0 {
				return nil, fmt.Errorf("trezor: no fields for struct %s", structRequest.GetName())
			}
			ack := &trezor.EthereumTypedDataStructAck{
				Members: make([]*trezor.EthereumTypedDataStructAck_EthereumStructMember, len(fields)),
			}
			for i, field := range fields {
				dt, name, byteLength, arrays, err := parseType(data, field)
				if err != nil {
					return nil, err
				}
				ubyteLength := uint32(byteLength)
				t := &trezor.EthereumTypedDataStructAck_EthereumFieldType{}
				inner := t
				for i := len(arrays) - 1; i >= 0; i-- {
					dataType := trezor.EthereumTypedDataStructAck_ARRAY
					inner.DataType = &dataType
					if arrays[i] != nil {
						length := uint32(*arrays[i])
						inner.Size = &length
					}
					inner.EntryType = &trezor.EthereumTypedDataStructAck_EthereumFieldType{}
					inner = inner.EntryType
				}
				var dataType trezor.EthereumTypedDataStructAck_EthereumDataType
				switch dt {
				case CustomType:
					inner.StructName = &name
					dataType = trezor.EthereumTypedDataStructAck_STRUCT
					members := uint32(len(data.Types[name]))
					inner.Size = &members
				case IntType:
					dataType = trezor.EthereumTypedDataStructAck_INT
					inner.Size = &ubyteLength
				case UintType:
					dataType = trezor.EthereumTypedDataStructAck_UINT
					inner.Size = &ubyteLength
				case AddressType:
					dataType = trezor.EthereumTypedDataStructAck_ADDRESS
				case BoolType:
					dataType = trezor.EthereumTypedDataStructAck_BOOL
				case StringType:
					dataType = trezor.EthereumTypedDataStructAck_STRING
				case FixedBytesType:
					dataType = trezor.EthereumTypedDataStructAck_BYTES
					inner.Size = &ubyteLength
				case BytesType:
					dataType = trezor.EthereumTypedDataStructAck_BYTES
				}
				inner.DataType = &dataType
				ack.Members[i] = &trezor.EthereumTypedDataStructAck_EthereumStructMember{
					Name: &field.Name,
					Type: t,
				}
			}
			req = ack
		case 2:
			structType := data.Types[data.PrimaryType]
			structValue := data.Message
			if valueRequest.MemberPath[0] == 0 {
				// populate with domain info
				structType = data.Types["EIP712Domain"]
				structValue = data.Domain.Map()
			}
			var value []byte
			for i := 1; i < len(valueRequest.MemberPath); i++ {
				p := valueRequest.MemberPath[i]
				if structType == nil {
					return nil, fmt.Errorf("trezor: no struct type for path %v", path)
				}
				if int(p) >= len(structType) {
					return nil, fmt.Errorf("trezor: invalid field index %d for struct %s", p, structRequest.GetName())
				}
				field := structType[p]
				nextValue := structValue[field.Name]
				dt, name, byteLength, arrays, err := parseType(data, field)
				if err != nil {
					return nil, err
				}
				if len(arrays) > 1 {
					nestedArray = true
				}
				for j := 0; j < len(arrays) && i < len(valueRequest.MemberPath)-1; i, j = i+1, j+1 {
					k := reflect.TypeOf(nextValue).Kind()
					if !(k == reflect.Array || k == reflect.Slice) {
						return nil, fmt.Errorf("trezor: expected array at path %v, got %T", valueRequest.MemberPath[:i+1], nextValue)
					}
					a := reflect.ValueOf(nextValue)
					p = valueRequest.MemberPath[i+1]
					if int(p) >= a.Len() {
						return nil, fmt.Errorf("trezor: invalid array index %d for path %v", p, valueRequest.MemberPath[:i+1])
					}
					nextValue = a.Index(int(p)).Interface()
				}
				k := reflect.TypeOf(nextValue).Kind()
				if i < len(valueRequest.MemberPath)-1 {
					if reflect.TypeOf(nextValue).Kind() != reflect.Map {
						return nil, fmt.Errorf("trezor: expected map at path %v, got %T", valueRequest.MemberPath[:i+1], nextValue)
					}
					structType = data.Types[name]
					structValue = nextValue.(apitypes.TypedDataMessage)
				} else if k == reflect.Array || k == reflect.Slice {
					// Array value, return length as uint16
					value = binary.BigEndian.AppendUint16([]byte{}, uint16(reflect.ValueOf(nextValue).Len()))
				} else {
					// Last value, encode it as a primitive value
					switch dt {
					case CustomType:
						return nil, fmt.Errorf("trezor: cannot encode custom type %s at path %v", name, valueRequest.MemberPath[:i+1])
					case IntType, UintType, AddressType, FixedBytesType:
						if str, ok := nextValue.(string); ok {
							value = common.FromHex(str)
						} else if f, ok := nextValue.(float64); ok {
							value = new(big.Int).SetInt64(int64(f)).Bytes()
						}
						if len(value) > byteLength {
							return nil, fmt.Errorf("trezor: value at path %v is too long (%d bytes, expected %d)", valueRequest.MemberPath[:i+1], len(value), byteLength)
						}
						for len(value) < byteLength {
							value = append([]byte{0}, value...)
						}
					case BoolType:
						if b, ok := nextValue.(bool); ok {
							if b {
								value = []byte{1}
							} else {
								value = []byte{0}
							}
						} else {
							return nil, fmt.Errorf("trezor: expected bool at path %v, got %T", valueRequest.MemberPath[:i+1], nextValue)
						}
					case StringType:
						if str, ok := nextValue.(string); ok {
							value = []byte(str)
						} else {
							return nil, fmt.Errorf("trezor: expected string at path %v, got %T", valueRequest.MemberPath[:i+1], nextValue)
						}
					case BytesType:
						if str, ok := nextValue.(string); ok {
							value = common.FromHex(str)
						} else {
							return nil, fmt.Errorf("trezor: expected bytes at path %v, got %T", valueRequest.MemberPath[:i+1], nextValue)
						}
					}
				}
			}
			req = &trezor.EthereumTypedDataValueAck{
				Value: value,
			}
		default:
			return nil, fmt.Errorf("trezor: unexpected reply index %d", n)
		}
	}
}
