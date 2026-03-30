const path = require("node:path");
const ImageMinimizerPlugin = require("image-minimizer-webpack-plugin");
const HtmlWebpackPlugin = require("html-webpack-plugin");
const TerserPlugin = require("terser-webpack-plugin");
const CssMinimizerPlugin = require("css-minimizer-webpack-plugin");

module.exports = {
    context: path.resolve(__dirname),
    entry: "./src/index.ts",
    output: {
        path: path.resolve(__dirname, "../dist"),
        publicPath: "",
        filename: "bundle.js"
    },
    module: {
        rules: [
            {
                test: /\.tsx?$/,
                use: "ts-loader",
                exclude: /node_modules/,
            },
            {
                test: /\.(png|svg)$/i,
                type: "asset/inline",
            },
            {
                test: /\.s[ac]ss$/i,
                use: [
                    "css-loader",
                    "sass-loader",
                ]
            },
        ],
    },
    resolve: {
        extensions: [".tsx", ".ts", ".js"],
    },
    optimization: {
        minimizer: [
            new CssMinimizerPlugin({
                minimizerOptions: {
                    preset: [
                        "default",
                        {
                            discardComments: {
                                removeAll: true
                            },
                        },
                    ],
                }
            }),
            new ImageMinimizerPlugin({
                minimizer: {
                    implementation: ImageMinimizerPlugin.imageminMinify,
                    options: {
                        plugins: [
                            "imagemin-pngquant",
                            "imagemin-svgo",
                        ],
                    },
                },
                loader: false,
            }),
            new TerserPlugin()
        ],
        splitChunks: {
            cacheGroups: {
                styles: {
                    name: "styles",
                    type: "css/mini-extract",
                    chunks: "all",
                    enforce: true,
                },
            },
        },
    },
    plugins: [
        new HtmlWebpackPlugin({
            title: "mod_repudiator",
            template: "./src/template.html",
            inject: false,
        }),
    ]
};
