// Re-export all parser tests in organized structure
import './parsers/lcov.test.js';
import './parsers/cobertura.test.js';
import './parsers/cobertura-edge-cases.test.js';
import './parsers/clover.test.js';
import './parsers/clover-edge-cases.test.js';
import './parsers/index.test.js';

// This file now serves as an entry point for all parser tests
// Individual parser tests are organized in the parsers/ subdirectory