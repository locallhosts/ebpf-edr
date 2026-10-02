                lp.Close()
                return nil, err
            }
            log.Printf("WARNING: optional probe %s (%s:%s) not attached: %v", h.prog, h.kind, h.target, err)
            continue
        }
        log.Printf("attached %s -> %s:%s", h.prog, h.kind, h.target)
    }

    rd, err := ringbuf.NewReader(coll.Maps["events"])
    if err != nil {
        lp.Close()
        return nil, fmt.Errorf("opening ring buffer reader: %w", err)
    }
    lp.reader = rd

    return lp, nil
}

func (lp *LoadedProbes) Read() (Event, error) {
    record, err := lp.reader.Read()
    if err != nil {
        return Event{}, err
    }
    if record.LostSamples > 0 {
        ringbufLoss.Add(float64(record.LostSamples))
    }
    return parseEvent(record.RawSample)
}

func (lp *LoadedProbes) Close() {
    if lp.reader != nil {
        _ = lp.reader.Close()
    }