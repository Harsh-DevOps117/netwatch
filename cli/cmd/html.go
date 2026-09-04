package cmd

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"
)

var htmlCmd = &cobra.Command{
	Use:   "html",
	Short: "Launch live HTML web dashboard",
	Run: func(cmd *cobra.Command, args []string) {
		http.HandleFunc("/", serveHTML)
		http.HandleFunc("/events", serveEvents)
		fmt.Println(lipgloss.NewStyle().Foreground(primary).Render("Starting live web dashboard at http://localhost:8080"))
		fmt.Println("Press Ctrl+C to stop.")
		if err := http.ListenAndServe(":8080", nil); err != nil {
			fmt.Printf("Server error: %v\n", err)
		}
	},
}

func init() {
	rootCmd.AddCommand(htmlCmd)
}

const htmlTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Netwatch Dashboard</title>
    <style>
        body {
            background-color: #111315;
            color: #ffffff;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 30px;
        }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 24px;
        }
        .header h1 {
            color: #ffffff;
            margin: 0;
            font-size: 1.5rem;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .header h1::before {
            content: "";
            display: inline-block;
            width: 12px;
            height: 12px;
            background: #FF5722;
            border-radius: 50%;
        }
        .grid {
            display: grid;
            grid-template-columns: 1fr 2fr;
            gap: 20px;
            margin-bottom: 20px;
        }
        .panel {
            background: #1A1D1F;
            border-radius: 16px;
            padding: 24px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.5);
            border: 1px solid rgba(255,255,255,0.05);
        }
        .panel h2 {
            margin-top: 0;
            color: #8E8E93;
            font-size: 0.9rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 16px;
        }
        .highlight-panel {
            background: linear-gradient(135deg, #FF5722, #D84315);
            border: none;
        }
        .highlight-panel h2 {
            color: rgba(255,255,255,0.7);
        }
        .big-metric {
            font-size: 3rem;
            font-weight: bold;
            margin-bottom: 8px;
        }
        .metric-label {
            color: #8E8E93;
            font-size: 0.9rem;
            margin-bottom: 4px;
            display: block;
        }
        .highlight-panel .big-metric {
            color: #ffffff;
        }
        .pill {
            background: #272B30;
            border-radius: 12px;
            padding: 12px 16px;
            display: flex;
            flex-direction: column;
            gap: 4px;
            font-size: 1rem;
            margin-bottom: 12px;
        }
        .pill .pill-title {
            color: #8E8E93;
            font-size: 0.8rem;
            text-transform: uppercase;
        }
        .pill .pill-val {
            font-weight: bold;
        }
        .pill.green .pill-val { color: #00C853; }
        .pill.red .pill-val { color: #FF3B30; }
        .pill.yellow .pill-val { color: #FFC107; }
        .pill.cyan .pill-val { color: #00BCD4; }
        
        .flow-container {
            display: flex;
            align-items: center;
            gap: 15px;
            margin-top: 30px;
        }
        .flow-step {
            background: rgba(255,255,255,0.1);
            padding: 10px 16px;
            border-radius: 8px;
            font-size: 0.9rem;
            color: rgba(255,255,255,0.7);
            flex: 1;
            text-align: center;
            transition: 0.3s;
        }
        .flow-step.active {
            background: #ffffff;
            color: #FF5722;
            font-weight: bold;
            box-shadow: 0 4px 10px rgba(0,0,0,0.2);
        }
        .flow-arrow {
            color: rgba(255,255,255,0.5);
            font-weight: bold;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            font-family: monospace;
            margin-top: 10px;
        }
        th, td {
            text-align: left;
            padding: 12px 10px;
            border-bottom: 1px solid #2C2C2E;
        }
        th {
            color: #8E8E93;
            font-size: 0.8rem;
            text-transform: uppercase;
        }
        td {
            color: #E3E3E3;
        }
        .alert-text { color: #FF5722; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Netwatch <span style="color: #8E8E93; font-weight: normal; font-size: 1rem;">| AI Security Dashboard</span></h1>
    </div>
    
    <div class="grid">
        <div class="panel">
            <h2>Threat Intelligence</h2>
            <span class="metric-label">Confidence Score</span>
            <div class="big-metric" id="confidence" style="color: #00C853;">0/100</div>
            
            <div style="margin-top: 30px; display: grid; grid-template-columns: 1fr 1fr; gap: 15px;">
                <div class="pill red">
                    <span class="pill-title">Attack Type</span>
                    <span class="pill-val" id="attackType">Scanning...</span>
                </div>
                <div class="pill yellow">
                    <span class="pill-title">Prevention Action</span>
                    <span class="pill-val" id="prevention">Evaluating...</span>
                </div>
            </div>
        </div>
        
        <div class="panel highlight-panel">
            <h2>Prediction Flow</h2>
            <div class="big-metric" id="prob">0%</div>
            <span style="color: rgba(255,255,255,0.8);">Probability of successful infiltration</span>
            
            <div class="flow-container" id="flowContainer">
                <div class="flow-step">Recon</div>
                <div class="flow-arrow">→</div>
                <div class="flow-step">Initial Access</div>
                <div class="flow-arrow">→</div>
                <div class="flow-step">Lateral Mvmt</div>
                <div class="flow-arrow">→</div>
                <div class="flow-step">Exfiltration</div>
            </div>
        </div>
    </div>

    <div class="panel">
        <h2>Live Packet Stream</h2>
        <table>
            <thead>
                <tr>
                    <th>TIME</th>
                    <th>SOURCE</th>
                    <th>DESTINATION</th>
                    <th>TYPE</th>
                    <th>SIZE</th>
                    <th>FLAG</th>
                </tr>
            </thead>
            <tbody id="logBody">
                <!-- Logs will appear here -->
            </tbody>
        </table>
    </div>

    <script>
        const evtSource = new EventSource("/events");
        const stages = ["Recon", "Initial Access", "Lateral Mvmt", "Exfiltration"];
        
        evtSource.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            const confEl = document.getElementById("confidence");
            confEl.innerText = data.stats.confidence + "/100";
            confEl.style.color = data.stats.confidence > 80 ? "#FF3B30" : (data.stats.confidence > 50 ? "#FFC107" : "#00C853");
            
            document.getElementById("attackType").innerText = data.stats.attackType;
            document.getElementById("prevention").innerText = data.stats.prevention;
            document.getElementById("prob").innerText = data.stats.prob + "%";

            // Update flow UI
            const flowHtml = stages.map((s, i) => {
                let cl = "flow-step";
                if (data.stats.flowStage === i) {
                    cl += " active";
                } else if (data.stats.flowStage > i) {
                    cl += " completed"; // Optional styling for past steps
                }
                return '<div class="' + cl + '">' + s + '</div>' + 
                       (i < stages.length - 1 ? '<div class="flow-arrow">→</div>' : '');
            }).join('');
            document.getElementById("flowContainer").innerHTML = flowHtml;

            const tbody = document.getElementById("logBody");
            const tr = document.createElement("tr");
            tr.innerHTML = "<td>" + data.log.time + "</td>" +
                           "<td>" + data.log.source + "</td>" +
                           "<td>" + data.log.dest + "</td>" +
                           "<td>" + data.log.proto + "</td>" +
                           "<td>" + data.log.size + "b</td>" +
                           "<td class='alert-text'>" + data.log.flags + "</td>";
            
            tbody.insertBefore(tr, tbody.firstChild);
            if (tbody.childNodes.length > 8) {
                tbody.removeChild(tbody.lastChild);
            }
        };
    </script>
</body>
</html>`

func serveHTML(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, htmlTemplate)
}

type SSEData struct {
	Stats struct {
		Confidence int    `json:"confidence"`
		Prob       int    `json:"prob"`
		AttackType string `json:"attackType"`
		Prevention string `json:"prevention"`
		FlowStage  int    `json:"flowStage"`
	} `json:"stats"`
	Log struct {
		Time   string `json:"time"`
		Source string `json:"source"`
		Dest   string `json:"dest"`
		Proto  string `json:"proto"`
		Size   int    `json:"size"`
		Flags  string `json:"flags"`
	} `json:"log"`
}

func serveEvents(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported!", http.StatusInternalServerError)
		return
	}

	ticker := time.NewTicker(1000 * time.Millisecond)
	defer ticker.Stop()
	
	attacks := []string{"SSH Brute Force", "SQL Injection", "DDoS SYN Flood", "Ransomware Lateral Mvmt", "Data Exfiltration"}
	preventions := []string{"Block IP", "Isolate Subnet", "Rate Limit", "Kill Connection", "Alert SecOps"}

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			proto := "TCP"
			rNum := rand.Intn(100)
			if rNum > 80 {
				proto = "UDP"
			} else if rNum > 95 {
				proto = "ICMP"
			}

			flags := []string{"SYN", "ACK", "PSH", "FIN"}
			flag := flags[rand.Intn(len(flags))]
			if proto != "TCP" {
				flag = "-"
			}

			data := SSEData{}
			data.Stats.Confidence = 60 + rand.Intn(35)
			data.Stats.Prob = 75 + rand.Intn(20)
			data.Stats.AttackType = attacks[rand.Intn(len(attacks))]
			data.Stats.Prevention = preventions[rand.Intn(len(preventions))]
			
			// Simulate moving through stages
			data.Stats.FlowStage = rand.Intn(4)

			data.Log.Time = time.Now().Format("15:04:05.000")
			data.Log.Source = fmt.Sprintf("192.168.1.%d:%d", rand.Intn(255), rand.Intn(60000)+1024)
			data.Log.Dest = fmt.Sprintf("10.0.0.%d:%d", rand.Intn(255), rand.Intn(1024)+1)
			data.Log.Proto = proto
			data.Log.Size = rand.Intn(1400) + 40
			data.Log.Flags = flag

			b, _ := json.Marshal(data)
			fmt.Fprintf(w, "data: %s\n\n", string(b))
			flusher.Flush()
		}
	}
}
