# Pull Request Creation Steps

## Step 2: Add your fork as remote (replace YOUR_USERNAME with your GitHub username)
```bash
git remote add fork https://github.com/YOUR_USERNAME/furious.git
```

## Step 3: Push your branch to your fork
```bash
git push fork fix-major-issues
```

## Step 4: Create Pull Request on GitHub
1. Go to your fork: https://github.com/YOUR_USERNAME/furious
2. You'll see a yellow banner saying "Compare & pull request" 
3. Click "Compare & pull request"
4. Fill in the details (see below)

## Pull Request Title:
```
Fix major issues: host detection, filtered ports, and add JSON output
```

## Pull Request Description:
```
This PR addresses three critical issues from the repository:

### Issues Fixed:
- **#12: Connect scan always returns "Host is down"** ✅
  - Enhanced latency tracking to properly detect host availability
  - Fixed error handling in connect scanner worker routines
  - Hosts now correctly show as "up" when they respond

- **#7: Filtered ports not populated** ✅  
  - Added proper timeout detection to classify ports as filtered
  - Enhanced port state classification logic
  - Filtered ports now correctly identified and displayed

- **#14: Add JSON output support** ✅
  - Implemented new `-j/--json` flag for structured output
  - JSON schema includes host, ports, latency, and status
  - Maintains full backward compatibility

### Technical Improvements:
- Better connection error classification (timeout vs refused vs unknown)
- Enhanced port state detection logic
- Improved scanner interface with JSON support methods
- More accurate response time measurement

### Testing:
- ✅ Connect scanning works properly, hosts detected as up
- ✅ Filtered ports correctly identified 
- ✅ JSON output provides clean, structured format
- ✅ Backward compatibility maintained
- ✅ Performance improvements verified

### Example Usage:
```bash
# Regular output
./furious -s connect -p 80,443,8080 google.com

# JSON output  
./furious -s connect -p 80,443,8080 -j google.com
```

This PR significantly improves the reliability and functionality of the scanner.
```

## Step 5: Submit the Pull Request
Click "Create pull request" button
```