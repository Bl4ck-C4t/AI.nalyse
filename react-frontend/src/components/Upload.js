import React, {useState} from 'react';
import axios from 'axios';
import 'bootstrap/dist/css/bootstrap.css';

const Upload = () => {
    const [file, setFile] = useState(null);
    const [message, setMessage] = useState('');
    const [vulns, setVulns] = useState('');

    const handleFileChange = (e) => {
        setFile(e.target.files[0]);
    };

    const vulnToHtml = (vuln) => {
        return `Between ${vuln[0].toString(16)} - ${vuln[1].toString(16)} | Confidence ${vuln[2].toFixed(2)}%<br />Z`
    }

    const handleSubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('file', file);

        try {
            const response = await axios.post('http://localhost:8000/api/upload/', formData, {
                headers: {
                    'Content-Type': 'multipart/form-data',
                },
            });

            if (response.status === 201) {
                setMessage('File uploaded successfully');
                var output = response.data.vulns
                console.log(output)
                setVulns(output);
            } else {
                setMessage('Error uploading file');
            }
        } catch (error) {
            setMessage('Error uploading file');
        }
    };

    return  (

        <div className="container mt-5">
            <h2 className="text-center">Upload a File</h2>
            <form onSubmit={handleSubmit} className="mb-3">
                <div className="form-group">
                    <input type="file" className="form-control" onChange={handleFileChange}/>
                </div>
                <button type="submit" className="btn btn-primary">Upload</button>
            </form>
            <p className="text-center">{message}</p>
            {vulns && (
                <div className="card mt-3">
                    <div className="card-header">
                        Total Vulnerabilities
                    </div>
                    <div className="card-body">
                        {
                            vulns.split("\n").map((line, index) => (
                                <p key={index}>{line}</p>
                            ))
                        }
                    </div>
                </div>
            )}
        </div>
    );
};

export default Upload;
