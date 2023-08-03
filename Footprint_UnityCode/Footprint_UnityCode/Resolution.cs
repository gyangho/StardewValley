using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class Resolution : MonoBehaviour
{
    //�ػ� ����
    public int screenWidth = 800;
    public int screenHeight = 600;

    void Start()
    {
        ChangeResolution();
    }

    void ChangeResolution()
    {
        Screen.fullScreen = false;
        Screen.SetResolution(screenWidth, screenHeight, Screen.fullScreen);
    }
}
