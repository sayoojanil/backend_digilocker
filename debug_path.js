
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const routesDir = path.join(__dirname, 'routes');

console.log('__dirname (backend):', __dirname);

const userId = '695d4efc86d684caa65b3840';
const fileUrl = 'http://localhost:5000/uploads/695d4efc86d684caa65b3840/file-1767726485325-241446355.pdf';

const basename = path.basename(fileUrl);
console.log('Basename:', basename);

// Simulate "view" route logic
const viewPath = path.join(routesDir, '..', 'uploads', userId, basename);
console.log('View path (from routes):', viewPath);

// Simulate broken "download" route logic
const downloadPathBroken = path.join(routesDir, '..', fileUrl);
console.log('Download path (broken):', downloadPathBroken);

// Proposed fix for download route
const relativePath = fileUrl.replace(/^https?:\/\/[^\/]+/, '');
const downloadPathFixed = path.join(routesDir, '..', relativePath);
console.log('Download path (fixed):', downloadPathFixed);
