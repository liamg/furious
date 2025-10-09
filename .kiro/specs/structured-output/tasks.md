# Implementation Plan

- [x] 1. Set up CLI flags and output format selection


  - Add --json/-j and --xml/-x flags to cobra command configuration
  - Implement output format validation and conflict detection
  - Add jsonOutput and xmlOutput boolean variables to cmd/root.go
  - _Requirements: 4.1, 4.2, 4.3, 4.4_



- [ ] 2. Create output management infrastructure
- [ ] 2.1 Define OutputManager interface and output format types
  - Create scan/output.go with OutputManager interface
  - Define OutputFormat enum (Text, JSON, XML)


  - Create factory function for output manager creation
  - _Requirements: 1.1, 2.1, 4.5_

- [ ] 2.2 Implement structured data models
  - Add JSON and XML tags to existing Result struct in scan/result.go
  - Create ScanMetadata struct with version, timing, and scan parameters
  - Create ScanSummary struct for statistics aggregation
  - Create StructuredOutput container struct
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 2.3 Create base output manager implementation
  - Implement TextOutputManager for existing text output behavior
  - Create output manager factory function
  - Add error handling for unsupported format combinations
  - _Requirements: 4.4, 4.5_

- [ ] 3. Implement JSON output support
- [ ] 3.1 Create JSON output writer
  - Implement JSONOutputManager struct and methods
  - Add JSON marshaling with proper formatting and indentation
  - Handle JSON-specific field formatting (duration to milliseconds)
  - _Requirements: 1.1, 1.4, 1.5_

- [ ] 3.2 Add JSON metadata collection
  - Collect scan start/end times and duration
  - Gather scan parameters (timeout, parallelism, scan type)
  - Include furious version information
  - Calculate summary statistics (hosts up/down, port counts)
  - _Requirements: 1.4, 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ]* 3.3 Write JSON output validation tests
  - Create unit tests for JSON schema validation
  - Test JSON output with various scan result combinations
  - Verify JSON parsing with standard libraries
  - _Requirements: 1.5_

- [ ] 4. Implement XML output support
- [ ] 4.1 Create XML output writer
  - Implement XMLOutputManager struct and methods
  - Add XML marshaling with proper structure and encoding
  - Handle XML-specific formatting and escaping
  - _Requirements: 2.1, 2.4, 2.5_

- [ ] 4.2 Add XML metadata and structure
  - Create XML root element and proper nesting
  - Handle XML array elements (ports, targets) correctly
  - Ensure well-formed XML output with proper encoding
  - _Requirements: 2.3, 2.4, 2.5_

- [ ]* 4.3 Write XML output validation tests
  - Create unit tests for XML schema validation


  - Test XML output with various scan result combinations
  - Verify XML parsing with standard libraries
  - _Requirements: 2.5_

- [ ] 5. Integrate structured output with scanner core
- [ ] 5.1 Modify main scan execution flow
  - Update cmd/root.go to use OutputManager instead of direct printing
  - Collect scan metadata during execution
  - Pass structured output flag to scanners
  - _Requirements: 1.2, 2.2, 4.5_

- [ ] 5.2 Update scanner interfaces for structured output
  - Modify Scanner interface to support OutputManager
  - Update ConnectScanner to use structured output when enabled
  - Update SynScanner to use structured output when enabled
  - Update DeviceScanner to use structured output when enabled
  - _Requirements: 5.1, 5.2, 5.3, 5.4_

- [ ] 5.3 Ensure consistent output across scanner types
  - Verify same JSON/XML schema for all scanner types
  - Handle device-specific fields (MAC, manufacturer) appropriately
  - Maintain consistent field names and data types
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ] 6. Add comprehensive error handling
- [ ] 6.1 Implement format validation and error reporting
  - Validate JSON output before writing
  - Validate XML output before writing
  - Provide clear error messages for format issues
  - _Requirements: 1.5, 2.5_

- [ ] 6.2 Handle missing data gracefully
  - Use omitempty tags for optional fields
  - Provide appropriate zero values for required fields
  - Handle device scanner specific fields when unavailable
  - _Requirements: 5.5, 6.4_

- [ ]* 6.3 Write error handling tests
  - Test behavior with invalid data structures
  - Test graceful handling of missing optional fields
  - Test error reporting for format validation failures
  - _Requirements: 6.4, 6.5_

- [ ] 7. Create comprehensive test suite
- [ ] 7.1 Write unit tests for output managers
  - Test JSON output manager functionality
  - Test XML output manager functionality
  - Test output format selection and validation
  - _Requirements: 1.5, 2.5, 4.4_

- [ ]* 7.2 Write integration tests for scanner compatibility
  - Test structured output with connect scanner
  - Test structured output with stealth scanner
  - Test structured output with device scanner
  - _Requirements: 5.1, 5.2, 5.3_

- [ ]* 7.3 Write end-to-end functionality tests
  - Test complete scan workflows with JSON output
  - Test complete scan workflows with XML output
  - Test metadata accuracy and completeness
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5_

- [ ] 8. Update documentation and examples
- [ ] 8.1 Add command-line help documentation
  - Update --help output to include new flags
  - Add usage examples for JSON and XML output
  - Document output format specifications
  - _Requirements: 4.1, 4.2_

- [ ] 8.2 Create output format documentation
  - Document JSON schema with examples
  - Document XML schema with examples
  - Provide integration examples for common use cases
  - _Requirements: 1.1, 2.1_