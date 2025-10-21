# 🔐 Hybrid Steganography Tool

A comprehensive Streamlit application for steganography that allows you to hide and extract messages within images using various methods.

## 🚀 Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the Streamlit application
streamlit run main.py
```

The application will open in your browser at `http://localhost:8501`.

## 📋 Features

### Currently Implemented
- **LSB (Least Significant Bit) Steganography** - Hide messages in the least significant bits of image pixels
- **Configurable bits per channel** (1-4 bits) for capacity vs quality tradeoff
- **Message embedding** with real-time capacity calculation
- **Message extraction** with verification against original
- **Message generator** for testing with specific byte sizes
- **Quality metrics** (MSE, PSNR, SSIM) for steganography evaluation
- **Robustness testing** against various image attacks

### Upcoming Features
- PVD (Pixel Value Differencing)
- EMD (Edge-Directed Method)
- DCT (Discrete Cosine Transform)
- DWT (Discrete Wavelet Transform)
- FFT (Fast Fourier Transform)
- Hybrid methods (combining frequency + spatial domains)

## 🎯 How to Use

### 1. Message Generator
1. Enter a base message or use the default test message
2. Specify target message size in bytes
3. Generate padded messages for capacity testing
4. Generated messages are automatically available in other tabs

### 2. Embed Message
1. Upload a cover image (PNG, JPG, JPEG, BMP, TIFF)
2. Use a message from the generator or enter your secret message
3. Adjust LSB parameters (bits per channel) using sidebar
4. Click "Embed Message" to generate the stego image
5. Download the resulting image with hidden message
6. Results are automatically available for extraction

### 3. Extract Message with Comprehensive Metrics
1. Use the stego image from previous embedding or upload a new one
2. Specify the bit length of the embedded message
3. **Optional Image Quality Metrics**: Upload original cover image for SSIM, PSNR, MSE comparison
4. **Optional Message Accuracy**: Provide original message for BER and accuracy calculation
5. **Optional Robustness Testing**: Test message survival against various attacks with BER heatmap
6. View comprehensive analysis including detailed BER results and attack resistance

**Features in Extract Tab:**
- **Image Quality Metrics**: SSIM, PSNR, MSE comparing original vs stego images
- **Message Accuracy**: BER calculation and message verification
- **Robustness Testing**: 9 attack types with color-coded BER heatmap
- **Detailed Analysis**: Expandable sections for each attack with performance ratings

## ⚙️ Configuration

### LSB Parameters
- **Bits per Channel**: 1-4 bits
  - 1 bit: Highest quality, lowest capacity
  - 4 bits: Highest capacity, lowest quality

### Supported Attacks for Robustness Testing
- JPEG Compression (various quality levels)
- Gaussian Noise
- Salt & Pepper Noise
- Cropping
- Rotation
- Scaling
- Gaussian Blur
- Sharpening
- Histogram Equalization

## 🏗️ Architecture

The application is built with:
- **Streamlit**: Web interface framework
- **OpenCV**: Image processing
- **NumPy**: Numerical operations
- **scikit-image**: Image quality metrics
- **Pillow**: Image manipulation

## 📁 Project Structure

```
├── main.py                    # Streamlit application entry point
├── requirements.txt           # Python dependencies
├── README.md                  # This file
└── src/                       # Core steganography modules
    ├── methods/               # Steganography algorithms
    │   └── spatial/
    │       ├── lsb.py         # LSB implementation
    │       ├── pvd.py         # PVD implementation
    │       └── emd.py         # EMD implementation
    ├── helpers/               # Utility modules
    │   ├── binary_massage.py  # Binary conversion utilities
    │   ├── create_massage.py  # Message generation
    │   ├── steganography_metrics.py  # Quality metrics
    │   └── robustness_tester.py      # Attack simulation
    └── s3/                    # S3 storage integration (optional)
```

## 🔧 Development

### Adding New Steganography Methods
1. Implement the method in `src/methods/` following the existing pattern
2. Add UI components in `main.py` for the new method
3. Include the method in the robustness testing suite

### Running Tests
```bash
# Test the application
streamlit run main.py

# Check dependencies
pip list
```

## 📊 Performance

### Capacity Estimation
For an image of size W×H with C channels:
- **Maximum bits**: W × H × C × bits_per_channel
- **Maximum bytes**: (W × H × C × bits_per_channel) ÷ 8

### Quality Tradeoffs
- **1 bit/channel**: ~38dB PSNR, excellent visual quality
- **2 bits/channel**: ~32dB PSNR, good visual quality
- **3 bits/channel**: ~26dB PSNR, noticeable artifacts
- **4 bits/channel**: ~20dB PSNR, significant artifacts

## 🛡️ Security Considerations

- LSB steganography is vulnerable to statistical analysis
- Always use robustness testing to evaluate message survivability
- Consider hybrid methods for better security in production use
- Messages are not encrypted by default - add encryption if needed

## 📝 License

This project is provided for educational and research purposes.

## 🤝 Contributing

Contributions welcome! Please ensure:
1. Code follows existing patterns
2. New methods include comprehensive testing
3. Documentation is updated
4. Dependencies are added to requirements.txt

---

**Built with ❤️ for the steganography community**