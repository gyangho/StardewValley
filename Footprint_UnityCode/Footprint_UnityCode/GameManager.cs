using System.Collections;
using System.Collections.Generic;
using UnityEngine;

public class GameManager : MonoBehaviour
{
    //����ȭ��
    public GameObject Cover;

    public void ClickButton()
    {
        Cover.SetActive(false);
    }
}