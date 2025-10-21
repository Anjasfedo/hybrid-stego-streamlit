import streamlit as st
import cv2
import numpy as np
import pandas as pd
import io
from PIL import Image
import os
import sys

# Add src directory to path for imports
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.methods.spatial.lsb import LSBSteganography
from src.helpers.create_massage import create_pattern_padded_message, my_message
from src.helpers.binary_massage import message_to_binary
from src.helpers.steganography_metrics import SteganographyMetrics
from src.helpers.robustness_tester import RobustnessTester

# Set page configuration
st.set_page_config(
    page_title="Hybrid Steganography Tool",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
    }
    .method-header {
        font-size: 1.5rem;
        color: #2ca02c;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 1rem;
        border-radius: 0.5rem;
        margin: 0.5rem 0;
    }
    .success-message {
        color: #2ca02c;
        font-weight: bold;
    }
    .error-message {
        color: #d62728;
        font-weight: bold;
    }
</style>
""", unsafe_allow_html=True)

# App title and description
st.markdown('<h1 class="main-header">🔐 Hybrid Steganography Tool</h1>', unsafe_allow_html=True)
st.markdown("""
This application provides a comprehensive suite of steganography methods for hiding messages within images.
Currently featuring **LSB (Least Significant Bit)** method with more methods coming soon!
""")

# Sidebar for configuration
st.sidebar.markdown("## ⚙️ Configuration")

# LSB Method Configuration
st.sidebar.markdown("### LSB Parameters")
bits_per_channel = st.sidebar.slider(
    "Bits per Channel",
    min_value=1,
    max_value=4,
    value=1,
    help="Number of bits to use per color channel. Higher values = more capacity but less quality."
)

# Main interface using tabs
tab1, tab2 = st.tabs(["📝 Embed Message", "🔍 Extract Message"])

# Helper functions
def load_image(uploaded_file):
    """Convert uploaded file to numpy array"""
    if uploaded_file is not None:
        # Read image file
        file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
        image = cv2.imdecode(file_bytes, cv2.IMREAD_COLOR)

        if image is None:
            st.error("❌ Invalid image file. Please upload a valid image.")
            return None

        # Convert BGR to RGB for display
        image_rgb = cv2.cvtColor(image, cv2.COLOR_BGR2RGB)
        return image, image_rgb
    return None, None

def display_image_comparison(original, stego, original_title="Original Image", stego_title="Stego Image"):
    """Display side by side image comparison"""
    col1, col2 = st.columns(2)

    with col1:
        st.markdown(f"**{original_title}**")
        st.image(original, use_container_width=True)

    with col2:
        st.markdown(f"**{stego_title}**")
        st.image(stego, use_container_width=True)

def calculate_image_capacity(image_shape, bits_per_channel):
    """Calculate maximum message capacity for an image"""
    height, width, channels = image_shape
    max_bits = height * width * channels * bits_per_channel
    max_bytes = max_bits // 8
    max_chars = max_bytes  # Approximate for UTF-8
    return max_bits, max_bytes, max_chars

# Tab 1: Embed Message (with integrated Message Generator)
with tab1:
    st.markdown('<h2 class="method-header">📝 Embed Message using LSB</h2>', unsafe_allow_html=True)

    # Message Generator Section
    with st.expander("🎯 Message Generator (Optional)", expanded=False):
        st.markdown("""
        Generate test messages with specific sizes for testing steganography capacity and performance.
        """)

        col1, col2 = st.columns([2, 1])

        with col1:
            base_message = st.text_area(
                "Base message:",
                value=my_message,
                height=100,
                help="The base message to be padded to the target size."
            )

            target_size = st.number_input(
                "Target message size (bytes):",
                min_value=1,
                max_value=10000,
                value=500,
                step=50,
                help="The exact byte size for the generated message."
            )

        with col2:
            st.markdown("### Message Info")
            if base_message:
                current_size = len(base_message.encode('utf-8'))
                st.metric("Current Size", f"{current_size} bytes")

                if target_size > current_size:
                    padding_needed = target_size - current_size
                    st.metric("Padding Needed", f"{padding_needed} bytes")
                else:
                    st.warning("⚠️ Target size is smaller than current message size!")

        if st.button("🎯 Generate Message", type="secondary", use_container_width=False):
            if base_message:
                generated_message = create_pattern_padded_message(base_message, target_size)
                actual_size = len(generated_message.encode('utf-8'))

                st.success("✅ Message generated successfully!")
                st.session_state.generated_message = generated_message

                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("### Generated Message")
                    st.text_area(
                        "Result:",
                        value=generated_message,
                        height=150,
                        disabled=True
                    )

                with col2:
                    st.markdown("### Message Statistics")
                    st.metric("Target Size", f"{target_size} bytes")
                    st.metric("Actual Size", f"{actual_size} bytes")
                    st.metric("Characters", f"{len(generated_message)}")

                    if actual_size == target_size:
                        st.success("✅ Perfect size match!")
                    else:
                        st.info(f"ℹ️ Size difference: {abs(actual_size - target_size)} bytes")

    st.markdown("---")

    # Embedding Section
    col1, col2 = st.columns([2, 1])

    with col1:
        st.markdown("### Upload Cover Image")
        cover_file = st.file_uploader(
            "Choose an image file",
            type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'],
            key="cover_upload"
        )

        if cover_file is not None:
            cover_image, cover_display = load_image(cover_file)
            if cover_image is not None:
                st.image(cover_display, caption="Uploaded Cover Image", use_container_width=True)

                # Calculate capacity
                max_bits, max_bytes, max_chars = calculate_image_capacity(
                    cover_image.shape, bits_per_channel
                )

                st.info(f"📊 **Image Capacity:** {max_bits:,} bits ({max_bytes:,} bytes ≈ {max_chars:,} characters)")

    with col2:
        st.markdown("### Message Configuration")

        # Option to use generated message
        use_generated = st.checkbox(
            "Use message from generator",
            value='generated_message' in st.session_state,
            help="Use the message generated above"
        )

        if use_generated and 'generated_message' in st.session_state:
            message_input = st.text_area(
                "Generated message:",
                value=st.session_state.generated_message,
                height=150,
                help="The generated message from the generator above."
            )
            st.info(f"📏 Message length: {len(message_input.encode('utf-8'))} bytes")
        else:
            message_input = st.text_area(
                "Enter your secret message:",
                value="This is a secret message! 🕵️‍♂️",
                height=150,
                help="The message you want to hide in the image."
            )

            # Auto-padding option
            auto_pad = st.checkbox(
                "Auto-pad message to test capacity",
                value=False,
                help="Automatically extend message to test maximum capacity"
            )

            if auto_pad:
                target_size = st.number_input(
                    "Target message size (bytes):",
                    min_value=1,
                    max_value=max_bytes if 'max_bytes' in locals() else 1000,
                    value=min(100, max_bytes if 'max_bytes' in locals() else 100),
                    step=10
                )
                message_input = create_pattern_padded_message(message_input, target_size)
                st.code(f"Padded message length: {len(message_input.encode('utf-8'))} bytes")

    # Embed button
    if st.button("🔐 Embed Message", type="primary", use_container_width=True):
        if cover_file is not None and message_input:
            try:
                with st.spinner("Embedding message..."):
                    # Initialize LSB steganography
                    lsb = LSBSteganography(bits_per_channel=bits_per_channel)

                    # Embed message
                    stego_image, bit_length = lsb.embed(cover_image, message_input)

                    # Convert to RGB for display
                    stego_display = cv2.cvtColor(stego_image, cv2.COLOR_BGR2RGB)

                    # Display results
                    st.success("✅ Message embedded successfully!")
                    st.markdown("### Result")
                    display_image_comparison(cover_display, stego_display)

                    # Show embedding bit_length info (copyable)
                    col1, col2 = st.columns([1, 1])
                    with col1:
                        st.info("📏 **Bit Length Used:**")
                    with col2:
                        # Make bit_length copyable using st.code
                        bit_length_text = f"{bit_length:,} bits ({bit_length//8} bytes)"
                        st.code(bit_length_text, language="text")

                    # Download button
                    st.markdown("### Download Stego Image")
                    stego_pil = Image.fromarray(stego_display)
                    img_buffer = io.BytesIO()
                    stego_pil.save(img_buffer, format='PNG')
                    st.download_button(
                        label="📥 Download Stego Image",
                        data=img_buffer.getvalue(),
                        file_name="stego_image.png",
                        mime="image/png"
                    )

                    # Store in session state for extraction tab
                    st.session_state.stego_image = stego_image
                    st.session_state.bit_length = bit_length
                    st.session_state.original_message = message_input

            except Exception as e:
                st.error(f"❌ Error embedding message: {str(e)}")
        else:
            st.warning("⚠️ Please upload an image and enter a message.")

# Tab 2: Extract Message
with tab2:
    st.markdown('<h2 class="method-header">🔍 Extract Message from LSB</h2>', unsafe_allow_html=True)

    # Option to use stego from previous tab or upload new one
    use_previous = st.checkbox(
        "Use stego image from previous embedding",
        value='stego_image' in st.session_state
    )

    stego_image = None
    stego_display = None
    bit_length = None
    original_message = None

    if use_previous and 'stego_image' in st.session_state:
        st.success("✅ Using stego image from previous embedding")
        stego_image = st.session_state.stego_image
        stego_display = cv2.cvtColor(stego_image, cv2.COLOR_BGR2RGB)
        st.image(stego_display, caption="Stego Image", use_container_width=True)
        bit_length = st.session_state.bit_length
        if 'original_message' in st.session_state:
            original_message = st.session_state.original_message
    else:
        st.markdown("### Upload Stego Image")
        stego_file = st.file_uploader(
            "Choose stego image file",
            type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'],
            key="stego_upload"
        )

        if stego_file is not None:
            stego_image, stego_display = load_image(stego_file)
            if stego_image is not None:
                st.image(stego_display, caption="Uploaded Stego Image", use_container_width=True)

                # Extraction parameters - auto-detect or manual
                st.markdown("### Extraction Parameters")
                auto_detect = st.checkbox(
                    "🔍 Auto-detect message length",
                    value=True,
                    help="Automatically detect the embedded message length"
                )

                if not auto_detect:
                    bit_length = st.number_input(
                        "Bit length of embedded message:",
                        min_value=1,
                        value=100,
                        step=1,
                        help="The exact number of bits that were embedded in the image."
                    )
                else:
                    bit_length = None
                    st.info("🔍 Will automatically detect message length during extraction")

    # Optional inputs for metrics calculation
    if stego_image is not None:
        st.markdown("### Optional Metrics Calculation")

        col1, col2 = st.columns(2)

        with col1:
            # Original image input for visual quality metrics
            enable_image_metrics = st.checkbox(
                "🖼️ Calculate Visual Quality Metrics",
                value=False,
                help="Calculate SSIM, PSNR, MSE by comparing original vs stego image"
            )

            if enable_image_metrics:
                original_file = st.file_uploader(
                    "📁 Original Cover Image (required for visual quality):",
                    type=['png', 'jpg', 'jpeg', 'bmp', 'tiff'],
                    key="original_image_upload",
                    help="Upload the original cover image to calculate visual quality metrics (SSIM, PSNR, MSE)"
                )

        with col2:
            # Original message input for message accuracy and robustness
            enable_message_analysis = st.checkbox(
                "💬 Analyze Message Accuracy & Robustness",
                value=original_message is not None,
                help="Calculate BER and test robustness by comparing extracted vs original message"
            )

            if enable_message_analysis:
                original_message_input = st.text_area(
                    "📝 Original Message (for accuracy & robustness):",
                    value=original_message if original_message else "",
                    height=100,
                    help="Provide the original message to calculate accuracy and run robustness tests"
                )

                # Robustness testing (only needs original message, not original image)
                st.markdown("#### 🛡️ Robustness Testing")

                enable_robustness = st.checkbox(
                    "⚡ Run Robustness Tests",
                    value=False,
                    help="Test message survival against various attacks (only needs original message)"
                )

                if enable_robustness:
                    test_attacks = st.multiselect(
                        "Select attacks to test:",
                        ["jpeg_compression", "gaussian_noise", "salt_pepper_noise",
                         "crop", "rotation", "scale", "gaussian_blur", "sharpen", "histogram_eq"],
                        default=["jpeg_compression", "gaussian_noise"],
                        help="Test how well the hidden message survives various image manipulations."
                    )

        # Extract button
        if st.button("🔍 Extract Message", type="primary", use_container_width=True):
            try:
                with st.spinner("Extracting message..."):
                    lsb = LSBSteganography(bits_per_channel=bits_per_channel)

                    if auto_detect or bit_length is None:
                        # Use auto-detection
                        extracted_message, detected_bit_length = lsb.extract_auto(stego_image)
                        if detected_bit_length > 0:
                            st.info(f"🔍 Auto-detected message length: {detected_bit_length} bits ({detected_bit_length//8} bytes)")
                            bit_length = detected_bit_length
                        else:
                            st.warning("⚠️ Could not auto-detect message. Please provide manual bit length.")
                            st.stop()
                    else:
                        # Use manual bit length
                        extracted_message, returned_bit_length = lsb.extract(stego_image, bit_length)

                    st.success("✅ Message extracted successfully!")
                    st.markdown("### Extracted Message")
                    st.code(extracted_message, language="text")

                    # Image Quality Metrics (if enabled)
                    if enable_image_metrics and original_file:
                        st.markdown("### 📊 Image Quality Metrics")

                        original_image, original_display = load_image(original_file)
                        if original_image is not None:
                            try:
                                    # Calculate image quality metrics
                                    metrics_calc = SteganographyMetrics(original_image, stego_image)
                                    all_metrics = metrics_calc.get_all_metrics()

                                    # Display metrics with beautiful cards
                                    col1, col2, col3 = st.columns(3)

                                    with col1:
                                        st.markdown("""
                                        <div class="metric-card">
                                            <h4>MSE</h4>
                                            <p style="font-size: 1.5rem; font-weight: bold; color: #1f77b4;">
                                                {:.6f}
                                            </p>
                                            <p style="font-size: 0.8rem; color: #666;">
                                                Mean Squared Error<br>
                                                Lower is better (0 = identical)
                                            </p>
                                        </div>
                                        """.format(all_metrics['mse']), unsafe_allow_html=True)

                                    with col2:
                                        st.markdown("""
                                        <div class="metric-card">
                                            <h4>PSNR</h4>
                                            <p style="font-size: 1.5rem; font-weight: bold; color: #2ca02c;">
                                                {:.2f} dB
                                            </p>
                                            <p style="font-size: 0.8rem; color: #666;">
                                                Peak Signal-to-Noise Ratio<br>
                                                Higher is better (∞ = identical)
                                            </p>
                                        </div>
                                        """.format(all_metrics['psnr']), unsafe_allow_html=True)

                                    with col3:
                                        st.markdown("""
                                        <div class="metric-card">
                                            <h4>SSIM</h4>
                                            <p style="font-size: 1.5rem; font-weight: bold; color: #ff7f0e;">
                                                {:.6f}
                                            </p>
                                            <p style="font-size: 0.8rem; color: #666;">
                                                Structural Similarity<br>
                                                Closer to 1.0 is better
                                            </p>
                                        </div>
                                        """.format(all_metrics['ssim']), unsafe_allow_html=True)

                                    # Visual comparison
                                    st.markdown("### Visual Comparison")
                                    original_display_rgb = cv2.cvtColor(original_image, cv2.COLOR_BGR2RGB)
                                    stego_display_rgb = cv2.cvtColor(stego_image, cv2.COLOR_BGR2RGB)
                                    display_image_comparison(original_display_rgb, stego_display_rgb,
                                                          "Original Image", "Stego Image")

                            except Exception as e:
                                st.error(f"❌ Error calculating image metrics: {str(e)}")

                    # Message Accuracy & Robustness Analysis (if enabled)
                    if enable_message_analysis and original_message_input:
                        st.markdown("### 🎯 Message Accuracy Metrics")

                        if len(original_message_input) > 0 and len(extracted_message) > 0:
                            # Convert to binary for BER calculation
                            original_binary = message_to_binary(original_message_input)
                            extracted_binary = message_to_binary(extracted_message)

                                # Calculate BER
                            min_length = min(len(original_binary), len(extracted_binary))
                            if min_length > 0:
                                    errors = sum(1 for i in range(min_length)
                                               if original_binary[i] != extracted_binary[i])
                                    ber = errors / min_length

                                    col1, col2, col3 = st.columns(3)
                                    with col1:
                                        st.metric("BER", f"{ber:.6f}")
                                    with col2:
                                        st.metric("Accuracy", f"{(1-ber)*100:.4f}%")
                                    with col3:
                                        if ber == 0:
                                            st.success("✅ Perfect!")
                                        elif ber < 0.001:
                                            st.info("🟡 Excellent")
                                        elif ber < 0.01:
                                            st.warning("🟠 Good")
                                        else:
                                            st.error("🔴 Poor")

                                # Message comparison
                            st.markdown("**Message Comparison:**")
                            col1, col2 = st.columns(2)
                            with col1:
                                    st.markdown("**Original:**")
                                    st.code(original_message_input)
                            with col2:
                                    st.markdown("**Extracted:**")
                                    st.code(extracted_message)

                            if extracted_message == original_message_input:
                                    st.success("✅ Perfect message match!")
                            else:
                                    st.warning("⚠️ Message differs from original.")

                        # Robustness Testing (if enabled - only needs original message)
                        if enable_robustness and test_attacks and original_message_input:
                            st.markdown("#### 🛡️ Robustness Testing - BER Heatmap")
                            with st.spinner("Running robustness tests..."):
                                    try:
                                        # Initialize robustness tester - note the constructor signature

                                        # Create a custom robustness tester that works with our interface
                                        results = {}

                                        # Map our attack names to the actual functions (complete configuration)
                                        attack_mapping = {
                                            'jpeg_compression': [
                                                {'name': 'JPEG', 'label': 'JPEG (Q=90)', 'quality': 90},
                                                {'name': 'JPEG', 'label': 'JPEG (Q=70)', 'quality': 70},
                                                {'name': 'JPEG', 'label': 'JPEG (Q=50)', 'quality': 50},
                                                {'name': 'JPEG', 'label': 'JPEG (Q=30)', 'quality': 30},
                                                {'name': 'JPEG', 'label': 'JPEG (Q=10)', 'quality': 10}
                                            ],
                                            'gaussian_noise': [
                                                {'name': 'Gaussian_Noise', 'label': 'Gaussian (σ=10)', 'sigma': 10},
                                                {'name': 'Gaussian_Noise', 'label': 'Gaussian (σ=25)', 'sigma': 25}
                                            ],
                                            'salt_pepper_noise': [
                                                {'name': 'SP_Noise', 'label': 'S&P (d=0.01)', 'density': 0.01},
                                                {'name': 'SP_Noise', 'label': 'S&P (d=0.03)', 'density': 0.03}
                                            ],
                                            'crop': [
                                                {'name': 'Crop', 'label': 'Crop (10%)', 'crop_percent': 10}
                                            ],
                                            'rotation': [
                                                {'name': 'Rotate', 'label': 'Rotate (3°)', 'angle': 3},
                                                {'name': 'Rotate', 'label': 'Rotate (9°)', 'angle': 9},
                                                {'name': 'Rotate', 'label': 'Rotate (18°)', 'angle': 18},
                                                {'name': 'Rotate', 'label': 'Rotate (36°)', 'angle': 36}
                                            ],
                                            'scale': [
                                                {'name': 'Scale', 'label': 'Scale (5%)', 'downscale_factor': 0.05},
                                                {'name': 'Scale', 'label': 'Scale (10%)', 'downscale_factor': 0.1},
                                                {'name': 'Scale', 'label': 'Scale (20%)', 'downscale_factor': 0.2},
                                                {'name': 'Scale', 'label': 'Scale (40%)', 'downscale_factor': 0.4},
                                                {'name': 'Scale', 'label': 'Scale (60%)', 'downscale_factor': 0.6},
                                                {'name': 'Scale', 'label': 'Scale (80%)', 'downscale_factor': 0.8},
                                                {'name': 'Scale', 'label': 'Scale (100%)', 'downscale_factor': 1.0},
                                                {'name': 'Scale', 'label': 'Scale (120%)', 'downscale_factor': 1.2},
                                                {'name': 'Scale', 'label': 'Scale (150%)', 'downscale_factor': 1.5},
                                                {'name': 'Scale', 'label': 'Scale (200%)', 'downscale_factor': 2.0}
                                            ],
                                            'gaussian_blur': [
                                                {'name': 'Blur', 'label': 'Blur (9x9)', 'kernel_size': (9, 9)},
                                                {'name': 'Blur', 'label': 'Blur (15x15)', 'kernel_size': (15, 15)},
                                                {'name': 'Blur', 'label': 'Blur (21x21)', 'kernel_size': (21, 21)},
                                                {'name': 'Blur', 'label': 'Blur (27x27)', 'kernel_size': (27, 27)},
                                                {'name': 'Blur', 'label': 'Blur (33x33)', 'kernel_size': (33, 33)},
                                                {'name': 'Blur', 'label': 'Blur (39x39)', 'kernel_size': (39, 39)}
                                            ],
                                            'sharpen': [
                                                {'name': 'Sharpen', 'label': 'Sharpen'}
                                            ],
                                            'histogram_eq': [
                                                {'name': 'HistEq', 'label': 'Hist. Equalize'}
                                            ]
                                        }

                                        # Create RobustnessTester with original message
                                        original_binary = message_to_binary(original_message_input)
                                        tester = RobustnessTester(lsb, original_binary)

                                        # Run tests for selected attack categories with error handling
                                        all_results = {}
                                        for attack_category in test_attacks:
                                            if attack_category in attack_mapping:
                                                category_configs = attack_mapping[attack_category]
                                                try:
                                                    category_results = tester.run_all_tests(stego_image, category_configs, returned_bit_length)
                                                    all_results.update(category_results)
                                                except Exception as e:
                                                    # If a specific attack fails, record it as 100% BER (complete failure)
                                                    st.warning(f"⚠️ Attack category '{attack_category}' failed: {str(e)}")
                                                    for config in category_configs:
                                                        all_results[config['label']] = 1.0  # 100% BER indicates complete failure

                                        st.success("✅ Robustness testing completed!")

                                        # Create comprehensive BER heatmap (styled like reference)
                                        st.markdown("#### 📊 BER Results Heatmap")

                                        if all_results:
                                            # Prepare data for comprehensive DataFrame
                                            attack_names = list(all_results.keys())
                                            ber_values = list(all_results.values())

                                            # Create detailed DataFrame with multiple columns
                                            df = pd.DataFrame({
                                                'Attack': attack_names,
                                                'BER (%)': [ber * 100 for ber in ber_values],
                                                'Survival': ['✅ Survived' if ber < 0.01 else '⚠️ Corrupted' if ber < 0.1 else '❌ Lost' for ber in ber_values],
                                                'Payload (Bytes)': [len(original_message_input.encode('utf-8'))] * len(attack_names),
                                                'Technique': ['LSB'] * len(attack_names),
                                                'Method BER': [ber * 100 for ber in ber_values],  # Same as BER column for compatibility
                                                'Average BER': [np.mean(ber_values) * 100] * len(attack_names)
                                            })

                                            # Add individual BER columns for each attack (like reference)
                                            for i, (attack, ber) in enumerate(zip(attack_names, ber_values)):
                                                # Create safe column name
                                                safe_name = attack.replace(' ', '_').replace('(', '').replace(')', '').replace('%', '').replace('°', '')
                                                df[f'BER_{safe_name}'] = [ber * 100] * len(attack_names)

                                            # Column ordering (like reference)
                                            base_cols = ['Attack', 'Payload (Bytes)', 'Technique', 'Method BER', 'Average BER']
                                            ber_cols = [col for col in df.columns if col.startswith('BER_') and col != 'BER (%)']
                                            other_cols = ['Survival']
                                            final_column_order = base_cols + ['BER (%)'] + ber_cols + other_cols

                                            # Reorder and sort
                                            df = df[final_column_order]
                                            df = df.sort_values(by=['Attack']).reset_index(drop=True)

                                            # Dynamic formatting dictionary
                                            style_format = {
                                                'BER (%)': '{:.4f}', 'Method BER': '{:.4f}', 'Average BER': '{:.4f}',
                                                'Payload (Bytes)': '{:.0f}'
                                            }
                                            for col in ber_cols:
                                                style_format[col] = '{:.4f}'

                                            # Apply basic styling without matplotlib gradients
                                            def color_ber_column(val):
                                                if val < 1:
                                                    return 'background-color: #d4edda; color: #155724'
                                                elif val < 5:
                                                    return 'background-color: #fff3cd; color: #856404'
                                                elif val < 10:
                                                    return 'background-color: #f8d7da; color: #721c24'
                                                else:
                                                    return 'background-color: #721c24; color: white'

                                            def style_payload(val):
                                                if val < 100:
                                                    return 'background-color: #cce5ff; color: #004085'
                                                elif val < 500:
                                                    return 'background-color: #b3d9ff; color: #004085'
                                                else:
                                                    return 'background-color: #99ccff; color: #003366'

                                            # Apply manual styling without matplotlib
                                            styled_df = (df.style
                                                .format(style_format)
                                                .applymap(color_ber_column, subset=['BER (%)', 'Method BER'])
                                                .applymap(color_ber_column, subset=ber_cols)
                                                .applymap(style_payload, subset=['Payload (Bytes)'])
                                            )

                                            st.dataframe(styled_df, use_container_width=True)

                                            # Overall statistics
                                            avg_ber = np.mean(ber_values)
                                            min_ber = np.min(ber_values)
                                            max_ber = np.max(ber_values)
                                            survived_attacks = sum(1 for ber in ber_values if ber < 0.01)

                                            col1, col2, col3, col4 = st.columns(4)
                                            with col1:
                                                st.metric("Average BER", f"{avg_ber:.4f}%")
                                            with col2:
                                                st.metric("Min BER", f"{min_ber:.4f}%")
                                            with col3:
                                                st.metric("Max BER", f"{max_ber:.4f}%")
                                            with col4:
                                                st.metric("Survived Attacks", f"{survived_attacks}/{len(all_results)}")

                                            # Detailed results in expandable sections
                                            st.markdown("#### Detailed Results")
                                            for attack_name, ber_value in all_results.items():
                                                with st.expander(f"🔬 {attack_name} - BER: {ber_value:.4f}%"):
                                                    col1, col2 = st.columns(2)

                                                    with col1:
                                                        st.markdown(f"**Performance:**")
                                                        if ber_value == 0:
                                                            st.success("✅ Perfect - No errors")
                                                        elif ber_value < 0.01:
                                                            st.info("🟡 Excellent - < 1% errors")
                                                        elif ber_value < 0.05:
                                                            st.warning("🟠 Good - < 5% errors")
                                                        elif ber_value < 0.1:
                                                            st.error("🔴 Poor - < 10% errors")
                                                        else:
                                                            st.error("❌ Very Poor - ≥ 10% errors")

                                                    with col2:
                                                        st.markdown(f"**Message Integrity:**")
                                                        if ber_value < 0.01:
                                                            st.success("✅ Message fully intact")
                                                        elif ber_value < 0.1:
                                                            st.warning("⚠️ Message partially corrupted")
                                                        else:
                                                            st.error("❌ Message severely corrupted")

                                    except Exception as e:
                                        st.error(f"❌ Error during robustness testing: {str(e)}")
                                        st.error("💡 This error might be due to image format compatibility issues. Try using a different image format (PNG or JPG) or check if the stego image was properly created.")

            except Exception as e:
                    st.error(f"❌ Error extracting message: {str(e)}")



# Footer
st.markdown("---")
st.markdown("""
<div style='text-align: center; color: #666; padding: 1rem;'>
    <p>🔐 <strong>Hybrid Steganography Tool</strong> - LSB Method Implementation</p>
    <p style='font-size: 0.8rem;'>More methods coming soon! • Built with Streamlit & OpenCV</p>
</div>
""", unsafe_allow_html=True)