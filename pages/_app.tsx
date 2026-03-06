import type { AppProps } from "next/app";

import AppChrome from "../src/components/AppChrome";
import "../src/styles/index.css";

export default function App({ Component, pageProps }: AppProps) {
  return (
    <AppChrome>
      <Component {...pageProps} />
    </AppChrome>
  );
}
