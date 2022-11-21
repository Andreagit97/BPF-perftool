package main

import (
	"encoding/json"
	"flag"
	"io/fs"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"
)

const (
	redisPrefix     = "redis_bench"
	redisOutputfile = "redis_report"

	/* Intrumentations */
	modernBPFInstr = "modern_bpf"
	BPFInstr       = "kmod"
	kmodInstr      = "bpf"
	noInstr        = "no_instrumentation"

	/* Redis JSON tags */
	instrTag      = "Instrumentation"
	GETTag        = "GET"
	SETTag        = "SET"
	requestsTag   = "Requests"
	iterationsTag = "Iterations"
)

var (
	resultsDir *string
	// redisStats   RedisStats
	syscallStats map[string]SyscallData
	outputSuffix *string
)

type RedisStats struct {
	GetData    map[string]float64 `json:"getData"`
	SetData    map[string]float64 `json:"setData"`
	Requests   float64            `json:"requests"`
	Iterations float64            `json:"iterations"`
	Used       bool               `json:"bool"`
}

type RedisOutput struct {
	ModernBPFRatio  map[string]float64 `json:"modernBPFRatio"`
	BPFRatio        map[string]float64 `json:"bpfRatio"`
	KmodRatio       map[string]float64 `json:"kmodRatio"`
	NoInstrRequests map[string]float64 `json:"noInstrRequests"`
	Requests        float64            `json:"requests"`
	Iterations      float64            `json:"iterations"`
}

type SyscallData struct {
	Intrumentations map[string]float64 `json:"instrumentations"`
	Samples         uint64             `json:"samples"`
	Iterations      uint64             `json:"iterations"`
}

func computeRatio(minor, major float64) float64 {
	return minor * 100 / major
}

func SearchFiles(root string, fn func(string) bool) []string {
	var files []string
	err := filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if fn(s) {
			files = append(files, s)
		}
		return nil
	})
	if err != nil {
		log.Fatal("Unable to walk through '", root, "': ", err)
	}
	return files
}

func parseRedisStats(stats *RedisStats) error {
	redisFiles := SearchFiles(*resultsDir, func(s string) bool {
		return filepath.Ext(s) == ".json" && strings.Contains(s, redisPrefix)
	})

	if len(redisFiles) == 0 {
		stats.Used = false
		log.Info("No Redis file to parse")
		return nil
	}

	stats.GetData = make(map[string]float64)
	stats.SetData = make(map[string]float64)

	for _, file := range redisFiles {
		jsonFile, err := os.Open(file)
		if err != nil {
			log.Fatal("Unable to open file '", file, "': ", err)
			return err
		}
		defer jsonFile.Close()

		byteValue, _ := ioutil.ReadAll(jsonFile)
		var result map[string]interface{}
		err = json.Unmarshal([]byte(byteValue), &result)
		if err != nil {
			log.Fatal("Unable to unmarshal file '", file, "': ", err)
			return err
		}

		stats.GetData[result[instrTag].(string)] = result[GETTag].(float64)
		stats.SetData[result[instrTag].(string)] = result[SETTag].(float64)
		stats.Requests = result[requestsTag].(float64)
		stats.Iterations = result[iterationsTag].(float64)
	}
	stats.Used = true

	return nil
}

func writeRedisReport(stats RedisStats, output *RedisOutput) error {

	output.ModernBPFRatio = make(map[string]float64)
	output.BPFRatio = make(map[string]float64)
	output.KmodRatio = make(map[string]float64)
	output.NoInstrRequests = make(map[string]float64)

	output.ModernBPFRatio[GETTag] = computeRatio(stats.GetData[modernBPFInstr], stats.GetData[noInstr])
	output.ModernBPFRatio[SETTag] = computeRatio(stats.SetData[modernBPFInstr], stats.SetData[noInstr])

	output.BPFRatio[GETTag] = computeRatio(stats.GetData[BPFInstr], stats.GetData[noInstr])
	output.BPFRatio[SETTag] = computeRatio(stats.SetData[BPFInstr], stats.SetData[noInstr])

	output.KmodRatio[GETTag] = computeRatio(stats.GetData[kmodInstr], stats.GetData[noInstr])
	output.KmodRatio[SETTag] = computeRatio(stats.SetData[kmodInstr], stats.SetData[noInstr])

	output.NoInstrRequests[GETTag] = stats.GetData[noInstr]
	output.NoInstrRequests[SETTag] = stats.SetData[noInstr]

	output.Requests = stats.Requests
	output.Iterations = stats.Iterations

	content, err := json.MarshalIndent(output, "", "	")
	if err != nil {
		log.Fatal("Unable to marshal redis output: ", err)
		return err
	}

	redis_out := redisOutputfile + *outputSuffix + ".json"
	if err := ioutil.WriteFile(redis_out, content, 0644); err != nil {
		log.Fatal("Unable to write the redis results: ", err)
		return err
	}
	return nil
}

// func plotRedis() {
// 	p := plot.New()
// 	p.Title.Text = "Redis Bench requests(" + string(redisStats.Requests) + ") iterations (" + string(redisStats.Iterations) + ")"
// 	p.Y.Label.Text = "Requests per second"
// 	w := vg.Points(20)

// 	barsA, err := plotter.NewBarChart(groupA, w)
// 	if err != nil {
// 		panic(err)
// 	}

// 	modernBPFGetRatio := computeRatio(redisStats.GetData[modernBPFInstr], redisStats.GetData[noInstr])
// 	modernBPFSetRatio := computeRatio(redisStats.SetData[modernBPFInstr], redisStats.SetData[noInstr])

// 	BPFGetRatio := computeRatio(redisStats.GetData[BPFInstr], redisStats.GetData[noInstr])
// 	BPFSetRatio := computeRatio(redisStats.GetData[BPFInstr], redisStats.GetData[noInstr])

// 	KmodGetRatio := computeRatio(redisStats.GetData[kmodInstr], redisStats.GetData[noInstr])
// 	KmodSetRatio := computeRatio(redisStats.GetData[kmodInstr], redisStats.GetData[noInstr])

// 	// modernBPF := plotter.Values{redisStats.GetData[modernBPFInstr], redisStats.SetData[modernBPFInstr]}
// 	// modernBPF := plotter.Values{redisStats.GetData[modernBPFInstr], redisStats.SetData[modernBPFInstr]}

// 	groupA := plotter.Values{25, 32, 34, 20, 25}
// 	groupB := plotter.Values{25, 32, 34, 20, 25}
// 	groupC := plotter.Values{12, 28, 15, 21, 8}

// 	p := plot.New()

// 	p.Title.Text = "Bar chart"
// 	p.Y.Label.Text = "Heights"

// 	w := vg.Points(10)

// 	barsA, err := plotter.NewBarChart(groupA, w)
// 	if err != nil {
// 		panic(err)
// 	}
// 	barsA.LineStyle.Width = vg.Length(0)
// 	barsA.Color = plotutil.Color(0)
// 	barsA.Offset = -w

// 	barsB, err := plotter.NewBarChart(groupB, w)
// 	if err != nil {
// 		panic(err)
// 	}
// 	barsB.LineStyle.Width = vg.Length(0)
// 	barsB.Color = plotutil.Color(1)

// 	barsC, err := plotter.NewBarChart(groupC, w)
// 	if err != nil {
// 		panic(err)
// 	}
// 	barsC.LineStyle.Width = vg.Length(0)
// 	barsC.Color = plotutil.Color(2)
// 	barsC.Offset = w

// 	p.Add(barsA, barsB, barsC)
// 	p.Legend.Add("Group A", barsA)
// 	p.Legend.Add("Group B", barsB)
// 	p.Legend.Add("Group C", barsC)
// 	p.Legend.Top = true
// 	p.NominalX("One", "Two", "Three", "Four", "Five")

// 	if err := p.Save(5*vg.Inch, 3*vg.Inch, "barchart2.png"); err != nil {
// 		panic(err)
// 	}
// }

func init() {
	cwd, err := os.Getwd()
	if err != nil {
		log.Fatal("Unable to get CWD: ", err)
	}

	resultsDir = flag.String("result-dir", cwd+"/../results", "path to the results dir")
	outputSuffix = flag.String("output-suf", "1", "suffix we append to the output files in order to not overwrite them")
}

func main() {
	flag.Parse()

	var redisStats RedisStats
	var redisOutput RedisOutput

	if err := parseRedisStats(&redisStats); err != nil {
		os.Exit(1)
	}

	/* we write reports and plot data only if we have available stats */
	if redisStats.Used {
		if err := writeRedisReport(redisStats, &redisOutput); err != nil {
			os.Exit(1)
		}

		// if err := plotRedisReport(redisOutput); err != nil {
		// 	os.Exit(1)
		// }
	}
}
