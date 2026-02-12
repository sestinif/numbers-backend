#!/bin/bash

# Script per caricare Numbers Backend su GitHub

echo "🚀 Deploy Numbers Backend su GitHub"
echo ""

# Chiedi username GitHub
read -p "Inserisci il tuo username GitHub: " GITHUB_USERNAME

# Inizializza Git
echo "📦 Inizializzazione Git..."
git init

# Aggiungi tutti i file
echo "📁 Aggiunta files..."
git add .

# Primo commit
echo "💾 Creazione commit..."
git commit -m "Initial commit - Numbers Backend API"

# Rinomina branch in main
echo "🌿 Rinomina branch in main..."
git branch -M main

# Aggiungi remote
echo "🔗 Collegamento a GitHub..."
git remote add origin https://github.com/$GITHUB_USERNAME/numbers-backend.git

# Push su GitHub
echo "⬆️ Upload su GitHub..."
git push -u origin main

echo ""
echo "✅ Deploy completato!"
echo "📍 Repository: https://github.com/$GITHUB_USERNAME/numbers-backend"
echo ""
echo "🎯 Prossimi passi:"
echo "1. Vai su Render Dashboard"
echo "2. New + → Web Service"
echo "3. Connetti il repository numbers-backend"
echo "4. Segui la guida GUIDA-DEPLOY-RENDER.md"
