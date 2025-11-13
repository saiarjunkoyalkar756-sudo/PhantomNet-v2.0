const { override, addPostcssPlugins } = require('customize-cra');
const path = require('path');

module.exports = override(
  addPostcssPlugins([
    require('tailwindcss')('./tailwind.config.js'), // Pass the tailwind config file
    require('autoprefixer')
  ]),
  (config) => {
    config.resolve.alias = {
      ...config.resolve.alias,
      src: path.resolve(__dirname, 'src'),
      hooks: path.resolve(__dirname, 'src/hooks'),
      services: path.resolve(__dirname, 'src/services'),
    };
    return config;
  }
);
