import pandas as pd
import os

directory = os.path.join(".", "csv", "packets")

for filename in os.listdir(directory): 
    if filename.endswith('.csv'): 
        file_path = os.path.join(directory, filename)

        df = pd.read_csv(file_path)

        if 'Stream index' in df.columns and 'Stream index.1' in df.columns:
            df.rename(columns={'Stream index': 'TCP Stream index', 'Stream index.1': 'UDP Stream index'}, inplace=True)

            df.to_csv(file_path, index=False)

        else:
            print(f"Skipping {filename}, column names already changed or not matching criteria.")



