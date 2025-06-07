import { useEffect } from "react";
import { useAuth } from "../auth/AuthProvider"

export function SecurePage() {
    const { auth } = useAuth();
    
    useEffect(() => {
        if (auth.accessToken) {
            fetch("https://localhost:7250/secure/user", {
                headers: {
                    "Authorization": `Bearer ${auth.accessToken}`
                }
            }).then(resp => {
                resp.text().then(data => console.log(data))
            })

            fetch("https://localhost:7250/secure/admin", {
                headers: {
                    "Authorization": `Bearer ${auth.accessToken}`
                }
            }).then(resp => {
                resp.text().then(data => console.log(data))
            })
        }
    }, [auth])

    return <div>
        
    </div>
}