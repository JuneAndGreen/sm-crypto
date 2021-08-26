const path = require('path');
const webpack = require('webpack');

module.exports = {
    entry: {
        sm2: './src/sm2/index.js',
        sm3: './src/sm3/index.js',
        sm4: './src/sm4/index.js',
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: '[name].js',
        library: '[name]',
        libraryTarget: 'umd',
    },
    module: {    
        loaders: [{    
            test: /\.js$/,    
            exclude: /node_modules/,    
            loader: 'babel-loader'    
        }]    
    },
    plugins: [
        new webpack.optimize.UglifyJsPlugin(),
    ]
};
