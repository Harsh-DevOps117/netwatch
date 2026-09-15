package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"netflow/config"
	"netflow/models"
	"netflow/pipeline"
)

func main() {
	cfg := config.LoadConfig()

	// Handle `-list-ifaces` flag
	if cfg.ListIfaces {
		fmt.Println("================================================================================")
		fmt.Println("               AVAILABLE NPCAP NETWORK CAPTURE INTERFACES                       ")
		fmt.Println("================================================================================")

		ifaces, err := pipeline.ListInterfaces()
		if err != nil {
			log.Fatalf("[Error] Failed to list interfaces: %v\nNote: Ensure Npcap driver is installed on Windows.", err)
		}

		if len(ifaces) == 0 {
			fmt.Println("No Npcap interfaces detected.")
			return
		}

		for i, iface := range ifaces {
			fmt.Printf("[%d] Type: %-10s | Description: %s\n", i+1, iface.Type, iface.Description)
			fmt.Printf("    Device Name: %s\n", iface.Name)
			if len(iface.IPs) > 0 {
				fmt.Printf("    IP Addresses: %v\n", iface.IPs)
			}
			fmt.Println("--------------------------------------------------------------------------------")
		}
		return
	}

	fmt.Println("================================================================================")
	fmt.Println("     NETFLOW PIPELINE & CICFLOWMETER ENGINE (Go + Npcap + Kafka + CSV)          ")
	fmt.Println("================================================================================")
	log.Printf("[Main] Target Kafka Brokers: %v | Topic: '%s'", cfg.KafkaBrokers, cfg.KafkaTopic)
	log.Printf("[Main] Rolling PCAP Aggregate Window: %v | CSV Output: '%s'", cfg.WindowDuration, cfg.CSVOutputPath)

	// Setup context with OS signal handling for graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Initialize Kafka Producer
	producer := pipeline.NewKafkaProducer(cfg)
	defer producer.Close()

	// Initialize CSV Writer for CICFlowMeter features
	csvWriter, err := pipeline.NewCSVWriter(cfg.CSVOutputPath)
	if err != nil {
		log.Fatalf("[Fatal Error] Failed to initialize CSV writer: %v", err)
	}

	// Initialize Rolling 2-minute PCAP Aggregator
	aggregator, err := pipeline.NewPCAPAggregator(cfg, csvWriter)
	if err != nil {
		log.Fatalf("[Fatal Error] Failed to initialize PCAP aggregator: %v", err)
	}

	// Communication channels
	packetChan := make(chan *models.PacketEvent, 10000)
	rawPktChan := make(chan gopacket.Packet, 10000)

	// Start rolling PCAP aggregator loop
	go aggregator.Start(ctx, rawPktChan)

	// Statistics counters
	var totalPackets uint64

	// Start packet capture (Live Npcap or Simulation)
	if err := pipeline.StartCapture(ctx, cfg, packetChan, rawPktChan); err != nil {
		log.Fatalf("[Fatal Error] Failed to start packet capturer: %v", err)
	}

	// Worker goroutine to read decoded packet events and push to Kafka
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case evt, ok := <-packetChan:
				if !ok {
					return
				}
				atomic.AddUint64(&totalPackets, 1)

				if err := producer.Publish(ctx, evt); err != nil {
					log.Printf("[Publish Warning] %v", err)
				}
			}
		}
	}()

	// Periodic metrics logging
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				count := atomic.LoadUint64(&totalPackets)
				log.Printf("[Metrics] Total packets captured & streamed to Kafka: %d", count)
			}
		}
	}()

	log.Println("[Main] Pipeline & CICFlowMeter Engine running. Press Ctrl+C to terminate.")
	<-ctx.Done()

	log.Println("[Main] Shutting down NetFlow Pipeline...")
	time.Sleep(500 * time.Millisecond)
	finalCount := atomic.LoadUint64(&totalPackets)
	log.Printf("[Main] Final stats: %d total packets ingested across interfaces.", finalCount)
}
