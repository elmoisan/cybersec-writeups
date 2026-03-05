# RF - AM Transmission

`Network` • `Easy` • `15 pts`

## TL;DR

Demodulate AM (Amplitude Modulation) radio signal from raw IQ samples to extract voice transmission containing the flag.

**Flag:** `[REDACTED]`

---

## Challenge Description

> You just joined a radio-frequency analysis team. For your first mission, they ask you to decode this transmission captured with a sampling rate of 60000 Hz.
>
> The flag is in lowercase.

---

## Recon

**Software Defined Radio (SDR)** allows processing radio signals digitally. The challenge provides:
- **Raw IQ samples** (In-phase/Quadrature components)
- **Sampling rate**: 60000 Hz
- **Modulation**: AM (Amplitude Modulation)

**AM Demodulation** extracts audio by calculating the signal envelope (magnitude of IQ samples).

---

## Exploitation

### Step 1: Understand the Raw IQ Format

The `.raw` file contains interleaved float32 samples: `I1, Q1, I2, Q2, ...`

**I (In-phase)** and **Q (Quadrature)** represent the complex signal:
```
Signal = I + jQ
Magnitude = sqrt(I² + Q²)
```

---

### Step 2: Demodulate AM Signal

**Python script (`am_demod.py`):**
```python
#!/usr/bin/env python3
import numpy as np
import struct
import wave

def read_raw_iq(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    samples = struct.unpack(f'{len(data)//4}f', data)
    i_samples = np.array(samples[0::2])
    q_samples = np.array(samples[1::2])
    return i_samples, q_samples

def am_demodulate(i_samples, q_samples):
    # Calculate envelope (magnitude)
    magnitude = np.sqrt(i_samples**2 + q_samples**2)
    
    # Remove DC component
    magnitude = magnitude - np.mean(magnitude)
    
    # Normalize
    magnitude = magnitude / np.max(np.abs(magnitude))
    
    return magnitude

def save_wav(audio, sample_rate, output_file):
    audio_int16 = np.int16(audio * 32767)
    with wave.open(output_file, 'w') as wav_file:
        wav_file.setnchannels(1)
        wav_file.setsampwidth(2)
        wav_file.setframerate(sample_rate)
        wav_file.writeframes(audio_int16.tobytes())

# Main
i_samples, q_samples = read_raw_iq('am_capture.raw')
audio = am_demodulate(i_samples, q_samples)
save_wav(audio, 60000, 'demodulated.wav')
```

**Execution:**
```bash
$ python3 am_demod.py
[*] Reading am_capture.raw...
[+] Loaded 1080000 IQ samples
[*] Demodulating AM signal...
[*] Saving audio to demodulated.wav...
[+] Audio saved successfully
```

---

### Step 3: Listen to Audio
```bash
aplay demodulated.wav
```

**Voice transmission (leetspeak):** "RF AM transmission"  
**Decoded:** `[REDACTED]`

---

### Step 4: Audio Enhancement (Optional)

For better clarity, apply filtering:
```python
from scipy import signal

# Lowpass filter (speech bandwidth)
nyquist = sample_rate / 2
b, a = signal.butter(4, 3000 / nyquist, btype='low')
magnitude = signal.filtfilt(b, a, magnitude)

# Highpass filter (remove DC drift)
b, a = signal.butter(2, 100 / nyquist, btype='high')
magnitude = signal.filtfilt(b, a, magnitude)
```

**Or use Audacity:**
- Effect → Noise Reduction
- Effect → Normalize
- Effect → Amplify

---

## Impact & Mitigation

### Real-World Implications

| Vulnerability | Impact |
|---------------|--------|
| **Unencrypted radio** | Voice/data interception |
| **Weak modulation** | Easy signal demodulation |
| **No authentication** | Unauthorized transmission |

**Attack Scenarios:**
1. **Military/police communications**: Intercept tactical communications
2. **Aviation**: Eavesdrop on air traffic control
3. **Amateur radio**: Monitor unencrypted transmissions
4. **IoT devices**: Capture sensor data (temperature, motion, etc.)
5. **Car key fobs**: Replay attacks on remote entry systems

**Why AM is insecure:**
- No encryption by default
- Simple demodulation (anyone with SDR can listen)
- Wide signal propagation (long-range interception)

---

### Secure Alternatives

| Technology | Security | Use Case |
|------------|----------|----------|
| **Digital Voice (DMR, P25)** | ✅ AES encryption | Emergency services, military |
| **Frequency hopping** | ✅ Anti-interception | Military tactical comms |
| **Spread spectrum** | ✅ Hard to detect/jam | GPS, WiFi, Bluetooth |
| **Encrypted VHF/UHF** | ✅ Voice scrambling | Secure radio networks |

**Best Practices:**
1. **Use digital modes with encryption** (DMR, P25, TETRA)
2. **Frequency hopping** to prevent targeted interception
3. **Low power transmission** to reduce interception range
4. **Directional antennas** to limit signal propagation
5. **Regular key rotation** for encrypted systems

---

## Key Takeaways

**Technical Skills:**
- Worked with raw IQ samples from SDR capture
- Performed AM demodulation (envelope detection)
- Understood I/Q signal representation
- Applied DSP filtering for audio enhancement

**Security Concepts:**
- Analog radio transmissions are inherently insecure
- Anyone with $20 SDR dongle can intercept unencrypted signals
- AM/FM modulation provides no confidentiality
- Modern systems use digital encryption (AES) for secure communications

---

## References

- [GNU Radio Tutorials](https://wiki.gnuradio.org/index.php/Tutorials)
- [RTL-SDR Quick Start Guide](https://www.rtl-sdr.com/rtl-sdr-quick-start-guide/)
- [Amplitude Modulation (AM) - Wikipedia](https://en.wikipedia.org/wiki/Amplitude_modulation)
- [DSP Guide - I/Q Data](http://www.dspguide.com/ch8/1.htm)
