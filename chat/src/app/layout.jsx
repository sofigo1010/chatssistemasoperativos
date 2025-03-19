export const metadata = {
    title: "Mi App",
    description: "Aplicación de ejemplo con Next.js",
  };
  
  export default function RootLayout({ children }) {
    return (
      <html lang="es">
        <body className="bg-gray-900 text-white">{children}</body>
      </html>
    );
  }
  