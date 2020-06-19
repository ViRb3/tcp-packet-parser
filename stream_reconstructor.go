package main

import "sort"

// Returns full ordered data.
func ReconstructPackets(packets map[uint32][]byte) []byte {
	var keys []uint32
	for k := range packets {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})
	var result []byte
	for _, key := range keys {
		result = append(result, packets[key]...)
	}
	return result
}
