package models

import (
	"fmt"
	"strconv"
)

// FlowFeature represents all 80+ statistical flow features extracted by CICFlowMeter.
type FlowFeature struct {
	FlowID                  string  `csv:"Flow ID"`
	SourceIP                string  `csv:"Source IP"`
	SourcePort              int     `csv:"Source Port"`
	DestinationIP           string  `csv:"Destination IP"`
	DestinationPort         int     `csv:"Destination Port"`
	Protocol                int     `csv:"Protocol"`
	Timestamp               string  `csv:"Timestamp"`
	FlowDuration            int64   `csv:"Flow Duration"` // Microseconds
	TotalFwdPackets         int64   `csv:"Total Fwd Packets"`
	TotalBackwardPackets    int64   `csv:"Total Backward Packets"`
	TotalLengthFwdPackets   int64   `csv:"Total Length of Fwd Packets"`
	TotalLengthBwdPackets   int64   `csv:"Total Length of Bwd Packets"`
	FwdPacketLengthMax      float64 `csv:"Fwd Packet Length Max"`
	FwdPacketLengthMin      float64 `csv:"Fwd Packet Length Min"`
	FwdPacketLengthMean     float64 `csv:"Fwd Packet Length Mean"`
	FwdPacketLengthStd      float64 `csv:"Fwd Packet Length Std"`
	BwdPacketLengthMax      float64 `csv:"Bwd Packet Length Max"`
	BwdPacketLengthMin      float64 `csv:"Bwd Packet Length Min"`
	BwdPacketLengthMean     float64 `csv:"Bwd Packet Length Mean"`
	BwdPacketLengthStd      float64 `csv:"Bwd Packet Length Std"`
	FlowBytesPerSec         float64 `csv:"Flow Bytes/s"`
	FlowPacketsPerSec       float64 `csv:"Flow Packets/s"`
	FlowIATMean             float64 `csv:"Flow IAT Mean"`
	FlowIATStd              float64 `csv:"Flow IAT Std"`
	FlowIATMax              float64 `csv:"Flow IAT Max"`
	FlowIATMin              float64 `csv:"Flow IAT Min"`
	FwdIATTotal             float64 `csv:"Fwd IAT Total"`
	FwdIATMean              float64 `csv:"Fwd IAT Mean"`
	FwdIATStd               float64 `csv:"Fwd IAT Std"`
	FwdIATMax               float64 `csv:"Fwd IAT Max"`
	FwdIATMin               float64 `csv:"Fwd IAT Min"`
	BwdIATTotal             float64 `csv:"Bwd IAT Total"`
	BwdIATMean              float64 `csv:"Bwd IAT Mean"`
	BwdIATStd               float64 `csv:"Bwd IAT Std"`
	BwdIATMax               float64 `csv:"Bwd IAT Max"`
	BwdIATMin               float64 `csv:"Bwd IAT Min"`
	FwdPSHFlags             int     `csv:"Fwd PSH Flags"`
	BwdPSHFlags             int     `csv:"Bwd PSH Flags"`
	FwdURGFlags             int     `csv:"Fwd URG Flags"`
	BwdURGFlags             int     `csv:"Bwd URG Flags"`
	FwdHeaderLength         int64   `csv:"Fwd Header Length"`
	BwdHeaderLength         int64   `csv:"Bwd Header Length"`
	FwdPacketsPerSec        float64 `csv:"Fwd Packets/s"`
	BwdPacketsPerSec        float64 `csv:"Bwd Packets/s"`
	MinPacketLength         float64 `csv:"Min Packet Length"`
	MaxPacketLength         float64 `csv:"Max Packet Length"`
	PacketLengthMean        float64 `csv:"Packet Length Mean"`
	PacketLengthStd         float64 `csv:"Packet Length Std"`
	PacketLengthVariance    float64 `csv:"Packet Length Variance"`
	FINFlagCount            int     `csv:"FIN Flag Count"`
	SYNFlagCount            int     `csv:"SYN Flag Count"`
	RSTFlagCount            int     `csv:"RST Flag Count"`
	PSHFlagCount            int     `csv:"PSH Flag Count"`
	ACKFlagCount            int     `csv:"ACK Flag Count"`
	URGFlagCount            int     `csv:"URG Flag Count"`
	CWEFlagCount            int     `csv:"CWE Flag Count"`
	ECEFlagCount            int     `csv:"ECE Flag Count"`
	DownUpRatio             float64 `csv:"Down/Up Ratio"`
	AveragePacketSize       float64 `csv:"Average Packet Size"`
	AvgFwdSegmentSize       float64 `csv:"Avg Fwd Segment Size"`
	AvgBwdSegmentSize       float64 `csv:"Avg Bwd Segment Size"`
	SubflowFwdPackets       int64   `csv:"Subflow Fwd Packets"`
	SubflowFwdBytes         int64   `csv:"Subflow Fwd Bytes"`
	SubflowBwdPackets       int64   `csv:"Subflow Bwd Packets"`
	SubflowBwdBytes         int64   `csv:"Subflow Bwd Bytes"`
	InitWinBytesForward     int     `csv:"Init_Win_bytes_forward"`
	InitWinBytesBackward    int     `csv:"Init_Win_bytes_backward"`
	ActDataPktFwd           int64   `csv:"act_data_pkt_fwd"`
	MinSegSizeForward       int64   `csv:"min_seg_size_forward"`
	ActiveMean              float64 `csv:"Active Mean"`
	ActiveStd               float64 `csv:"Active Std"`
	ActiveMax               float64 `csv:"Active Max"`
	ActiveMin               float64 `csv:"Active Min"`
	IdleMean                float64 `csv:"Idle Mean"`
	IdleStd                 float64 `csv:"Idle Std"`
	IdleMax                 float64 `csv:"Idle Max"`
	IdleMin                 float64 `csv:"Idle Min"`
}

// CSVHeaders returns standard CICFlowMeter CSV column names.
func CSVHeaders() []string {
	return []string{
		"Flow ID", "Source IP", "Source Port", "Destination IP", "Destination Port",
		"Protocol", "Timestamp", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
		"Total Length of Fwd Packets", "Total Length of Bwd Packets",
		"Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
		"Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
		"Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
		"Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
		"Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
		"Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
		"Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
		"Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
		"FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
		"CWE Flag Count", "ECE Flag Count", "Down/Up Ratio", "Average Packet Size",
		"Avg Fwd Segment Size", "Avg Bwd Segment Size", "Subflow Fwd Packets", "Subflow Fwd Bytes",
		"Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward", "Init_Win_bytes_backward",
		"act_data_pkt_fwd", "min_seg_size_forward", "Active Mean", "Active Std", "Active Max", "Active Min",
		"Idle Mean", "Idle Std", "Idle Max", "Idle Min",
	}
}

// ToCSVRow serializes a FlowFeature into an ordered slice of strings matching CSVHeaders.
func (f *FlowFeature) ToCSVRow() []string {
	return []string{
		f.FlowID,
		f.SourceIP,
		strconv.Itoa(f.SourcePort),
		f.DestinationIP,
		strconv.Itoa(f.DestinationPort),
		strconv.Itoa(f.Protocol),
		f.Timestamp,
		strconv.FormatInt(f.FlowDuration, 10),
		strconv.FormatInt(f.TotalFwdPackets, 10),
		strconv.FormatInt(f.TotalBackwardPackets, 10),
		strconv.FormatInt(f.TotalLengthFwdPackets, 10),
		strconv.FormatInt(f.TotalLengthBwdPackets, 10),
		fmt.Sprintf("%.6f", f.FwdPacketLengthMax),
		fmt.Sprintf("%.6f", f.FwdPacketLengthMin),
		fmt.Sprintf("%.6f", f.FwdPacketLengthMean),
		fmt.Sprintf("%.6f", f.FwdPacketLengthStd),
		fmt.Sprintf("%.6f", f.BwdPacketLengthMax),
		fmt.Sprintf("%.6f", f.BwdPacketLengthMin),
		fmt.Sprintf("%.6f", f.BwdPacketLengthMean),
		fmt.Sprintf("%.6f", f.BwdPacketLengthStd),
		fmt.Sprintf("%.6f", f.FlowBytesPerSec),
		fmt.Sprintf("%.6f", f.FlowPacketsPerSec),
		fmt.Sprintf("%.6f", f.FlowIATMean),
		fmt.Sprintf("%.6f", f.FlowIATStd),
		fmt.Sprintf("%.6f", f.FlowIATMax),
		fmt.Sprintf("%.6f", f.FlowIATMin),
		fmt.Sprintf("%.6f", f.FwdIATTotal),
		fmt.Sprintf("%.6f", f.FwdIATMean),
		fmt.Sprintf("%.6f", f.FwdIATStd),
		fmt.Sprintf("%.6f", f.FwdIATMax),
		fmt.Sprintf("%.6f", f.FwdIATMin),
		fmt.Sprintf("%.6f", f.BwdIATTotal),
		fmt.Sprintf("%.6f", f.BwdIATMean),
		fmt.Sprintf("%.6f", f.BwdIATStd),
		fmt.Sprintf("%.6f", f.BwdIATMax),
		fmt.Sprintf("%.6f", f.BwdIATMin),
		strconv.Itoa(f.FwdPSHFlags),
		strconv.Itoa(f.BwdPSHFlags),
		strconv.Itoa(f.FwdURGFlags),
		strconv.Itoa(f.BwdURGFlags),
		strconv.FormatInt(f.FwdHeaderLength, 10),
		strconv.FormatInt(f.BwdHeaderLength, 10),
		fmt.Sprintf("%.6f", f.FwdPacketsPerSec),
		fmt.Sprintf("%.6f", f.BwdPacketsPerSec),
		fmt.Sprintf("%.6f", f.MinPacketLength),
		fmt.Sprintf("%.6f", f.MaxPacketLength),
		fmt.Sprintf("%.6f", f.PacketLengthMean),
		fmt.Sprintf("%.6f", f.PacketLengthStd),
		fmt.Sprintf("%.6f", f.PacketLengthVariance),
		strconv.Itoa(f.FINFlagCount),
		strconv.Itoa(f.SYNFlagCount),
		strconv.Itoa(f.RSTFlagCount),
		strconv.Itoa(f.PSHFlagCount),
		strconv.Itoa(f.ACKFlagCount),
		strconv.Itoa(f.URGFlagCount),
		strconv.Itoa(f.CWEFlagCount),
		strconv.Itoa(f.ECEFlagCount),
		fmt.Sprintf("%.6f", f.DownUpRatio),
		fmt.Sprintf("%.6f", f.AveragePacketSize),
		fmt.Sprintf("%.6f", f.AvgFwdSegmentSize),
		fmt.Sprintf("%.6f", f.AvgBwdSegmentSize),
		strconv.FormatInt(f.SubflowFwdPackets, 10),
		strconv.FormatInt(f.SubflowFwdBytes, 10),
		strconv.FormatInt(f.SubflowBwdPackets, 10),
		strconv.FormatInt(f.SubflowBwdBytes, 10),
		strconv.Itoa(f.InitWinBytesForward),
		strconv.Itoa(f.InitWinBytesBackward),
		strconv.FormatInt(f.ActDataPktFwd, 10),
		strconv.FormatInt(f.MinSegSizeForward, 10),
		fmt.Sprintf("%.6f", f.ActiveMean),
		fmt.Sprintf("%.6f", f.ActiveStd),
		fmt.Sprintf("%.6f", f.ActiveMax),
		fmt.Sprintf("%.6f", f.ActiveMin),
		fmt.Sprintf("%.6f", f.IdleMean),
		fmt.Sprintf("%.6f", f.IdleStd),
		fmt.Sprintf("%.6f", f.IdleMax),
		fmt.Sprintf("%.6f", f.IdleMin),
	}
}
