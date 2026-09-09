package pipeline

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/segmentio/kafka-go"
	"netflow/config"
	"netflow/models"
)

// KafkaProducer manages asynchronous message publishing to Apache Kafka.
type KafkaProducer struct {
	writer *kafka.Writer
	topic  string
}

// EnsureTopicExists attempts to create the target topic if it does not already exist on the Kafka broker.
func EnsureTopicExists(brokers []string, topic string) {
	if len(brokers) == 0 {
		return
	}
	conn, err := kafka.Dial("tcp", brokers[0])
	if err != nil {
		log.Printf("[Kafka Producer Warning] Could not connect to Kafka broker %s to check topic: %v", brokers[0], err)
		return
	}
	defer conn.Close()

	topicConfig := kafka.TopicConfig{
		Topic:             topic,
		NumPartitions:     1,
		ReplicationFactor: 1,
	}

	err = conn.CreateTopics(topicConfig)
	if err != nil {
		// Ignored if topic already exists or auto-created
		log.Printf("[Kafka Producer Note] Topic creation check for '%s': %v", topic, err)
	} else {
		log.Printf("[Kafka Producer] Successfully ensured topic '%s' exists on broker.", topic)
	}
}

// NewKafkaProducer creates and initializes a Kafka writer using config settings.
func NewKafkaProducer(cfg *config.Config) *KafkaProducer {
	EnsureTopicExists(cfg.KafkaBrokers, cfg.KafkaTopic)

	writer := &kafka.Writer{
		Addr:                   kafka.TCP(cfg.KafkaBrokers...),
		Topic:                  cfg.KafkaTopic,
		Balancer:               &kafka.LeastBytes{},
		BatchSize:              cfg.BatchSize,
		BatchTimeout:           cfg.BatchTimeout,
		Async:                  true, // Asynchronous batch publishing for high-throughput packet ingestion
		AllowAutoTopicCreation: true,
		Completion: func(messages []kafka.Message, err error) {
			if err != nil {
				log.Printf("[Kafka Producer Error] Failed to publish batch of %d messages: %v", len(messages), err)
			}
		},
	}

	log.Printf("[Kafka Producer] Initialized for brokers %v on topic '%s'", cfg.KafkaBrokers, cfg.KafkaTopic)

	return &KafkaProducer{
		writer: writer,
		topic:  cfg.KafkaTopic,
	}
}

// Publish serializes a PacketEvent to JSON and pushes it to Kafka.
func (p *KafkaProducer) Publish(ctx context.Context, evt *models.PacketEvent) error {
	if evt == nil {
		return nil
	}

	data, err := json.Marshal(evt)
	if err != nil {
		return fmt.Errorf("failed to marshal packet event: %w", err)
	}

	msg := kafka.Message{
		Key:   []byte(evt.InterfaceName),
		Value: data,
		Time:  evt.Timestamp,
	}

	err = p.writer.WriteMessages(ctx, msg)
	if err != nil {
		return fmt.Errorf("failed to write message to kafka: %w", err)
	}

	return nil
}

// Close flushes buffered messages and releases resources.
func (p *KafkaProducer) Close() error {
	log.Println("[Kafka Producer] Closing and flushing remaining messages...")
	if err := p.writer.Close(); err != nil {
		return fmt.Errorf("error closing kafka writer: %w", err)
	}
	log.Println("[Kafka Producer] Closed successfully.")
	return nil
}
