# Wiremock Management System - Updated Implementation

## 🎨 **UI Improvements Made**

### **1. Enhanced Color Scheme**
- **Background**: Changed from red-orange gradient to professional dark blue-gray gradient (`#2c3e50` to `#34495e`)
- **Statistics Cards**: Now have blue gradient backgrounds with better contrast and separation
- **Buttons**: Updated with distinct color schemes:
  - **Refresh Mappings**: Green gradient (`#27ae60` to `#229954`)
  - **View Logs**: Purple gradient (`#8e44ad` to `#7d3c98`)
  - **Other Actions**: Red gradient (`#e74c3c` to `#c0392b`)

### **2. Postman-Style Response Section**
- **Response JSON**: Now displays with black background (`#1e1e1e`) and orange text (`#ff8c00`)
- **Syntax Highlighting**: Color-coded JSON elements:
  - Keys: Red (`#ff6b6b`)
  - Strings: Green (`#98d982`)
  - Numbers: Yellow (`#ffd93d`)
  - Booleans: Orange (`#ff8c00`)
  - Null values: Gray (`#808080`)

### **3. Statistics Cards Enhancement**
- Added proper background colors and borders for better visual separation
- Enhanced shadows and gradients for depth
- Better contrast for readability

## 🔒 **Security Improvements**

### **1. WireMockEnv Class Implementation**
- Created `dashboard/wiremock_config.py` with proper configuration management
- Removed hardcoded credentials from views
- Supports both environment variables and config file loading
- Fallback to secure defaults

### **2. Configuration Management**
- **Primary**: Environment variables (most secure)
- **Secondary**: `wiremock_config.json` file
- **Fallback**: Secure default values
- **Sample Config**: Provided `wiremock_config.json` with your credentials

## 🚀 **How to Use**

### **1. Configuration Setup**
```bash
# Option 1: Environment Variables (Recommended)
export WIREMOCK_BASEURL="https://wiremock.ntx.ir"
export WIREMOCK_ADMIN_USERNAME="nobitex"
export WIREMOCK_ADMIN_PASSWORD="n9d8c2398ncnuic23y9pYIfbtobfco23vt8bc823btoiTYUTU"

# Option 2: Config File (Already provided)
# Edit wiremock_config.json with your settings
```

### **2. Access the Interface**
1. Go to `http://127.0.0.1:8000/`
2. Click on the **Wiremock** card
3. View mappings with the new Postman-style response display
4. Use the colored buttons for different actions

## 🎯 **Key Features**

### **Visual Enhancements**
- ✅ **Statistics Cards**: Blue gradient backgrounds with proper separation
- ✅ **Button Colors**: Distinct colors for different actions
- ✅ **Response Section**: Postman-style black background with orange text
- ✅ **Overall Theme**: Professional dark blue-gray gradient
- ✅ **Better Contrast**: Improved readability and visual hierarchy

### **Security Features**
- ✅ **No Hardcoded Credentials**: All credentials moved to configuration
- ✅ **Environment Variable Support**: Most secure option
- ✅ **Config File Support**: Easy deployment option
- ✅ **Secure Fallbacks**: Safe default values

### **Functionality**
- ✅ **Real-time Mappings**: Live display of all stub mappings
- ✅ **Request Logs**: Detailed request/response monitoring
- ✅ **Postman-style JSON**: Enhanced response viewing
- ✅ **Responsive Design**: Works on all screen sizes
- ✅ **Error Handling**: Comprehensive error management

## 📁 **File Structure**

```
dashboard/
├── wiremock_config.py          # Configuration management
├── views.py                    # Updated views with security
└── templates/dashboard/
    └── wiremock_dashboard.html # Enhanced UI template

wiremock_config.json            # Sample configuration file
```

## 🔧 **Technical Details**

### **Color Palette**
- **Primary Background**: `#2c3e50` to `#34495e` (Dark blue-gray)
- **Statistics Cards**: `#3498db` to `#2980b9` (Blue)
- **Refresh Button**: `#27ae60` to `#229954` (Green)
- **Logs Button**: `#8e44ad` to `#7d3c98` (Purple)
- **Response Background**: `#1e1e1e` (Black)
- **Response Text**: `#ff8c00` (Orange)

### **Security Implementation**
- **WireMockEnv Class**: Pydantic-based configuration validation
- **Environment Priority**: Environment variables > Config file > Defaults
- **Credential Management**: Centralized and secure
- **Error Handling**: Graceful fallbacks for missing configuration

The system now provides a beautiful, secure, and professional interface for managing your Wiremock server with Postman-style response viewing and enhanced visual design!
